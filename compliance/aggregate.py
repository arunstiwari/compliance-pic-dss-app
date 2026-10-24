#!/usr/bin/env python3
"""Compliance gate: turns scanner reports into a PCI DSS / ISO 27001 control matrix.

Reads compliance/controls.yaml and the JSON reports in --reports-dir, then writes:
  compliance-matrix.md    (GitHub job summary / PR comment)
  compliance-matrix.html  (shareable evidence page)
  compliance-results.json (machine-readable, for dashboards or GRC tools)

Exit code 1 when any blocking control FAILs (with --strict, also when a blocking
control's evidence is missing). Secret values from Gitleaks are never printed.

Usage:
  python compliance/aggregate.py --reports-dir reports [--out-dir reports] [--strict]
"""
from __future__ import annotations

import argparse
import datetime as dt
import html
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

PASS, WARN, FAIL, NOT_RUN = "PASS", "WARN", "FAIL", "NOT_RUN"
RANK = {PASS: 0, NOT_RUN: 1, WARN: 2, FAIL: 3}
ICON = {PASS: "✅", WARN: "⚠️", FAIL: "❌", NOT_RUN: "⏭️"}
MAX_FINDINGS = 8


@dataclass
class CheckResult:
    check_id: str
    title: str
    tool: str
    status: str
    summary: str
    findings: list[str] = field(default_factory=list)
    exceptions: list[str] = field(default_factory=list)
    evidence: str = ""


# --------------------------------------------------------------------------- helpers
def load_json(path: Path):
    try:
        with path.open(encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        return None
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Report {path} is not valid JSON: {exc}")


def missing(check_id, cfg, report) -> CheckResult:
    return CheckResult(check_id, cfg["title"], cfg["tool"], NOT_RUN,
                       f"No evidence: {report} was not produced", evidence=report)


def verdict(cfg, failed: bool) -> str:
    if not failed:
        return PASS
    return WARN if cfg.get("on_fail") == "warn" else FAIL


# --------------------------------------------------------------------------- parsers
def check_gitleaks(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return missing(cid, cfg, cfg["report"])
    # Never echo f["Secret"] or f["Match"]: the report is evidence, not a leak.
    findings = [f'{f.get("RuleID")} in {f.get("File")}:{f.get("StartLine")}' for f in data]
    return CheckResult(cid, cfg["title"], "gitleaks", verdict(cfg, bool(findings)),
                       f"{len(findings)} secret(s) detected", findings, evidence=cfg["report"])


def check_semgrep(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return missing(cid, cfg, cfg["report"])
    rules = cfg.get("rules")
    severities = set(cfg.get("severities", ["ERROR"]))
    hits = []
    for r in data.get("results", []):
        rule = r["check_id"]
        if rules and not any(rule == x or rule.endswith("." + x) for x in rules):
            continue
        if r.get("extra", {}).get("severity", "ERROR") not in severities:
            continue
        hits.append(f'{rule.split(".")[-1]} at {r["path"]}:{r["start"]["line"]}')
    return CheckResult(cid, cfg["title"], "semgrep", verdict(cfg, bool(hits)),
                       f"{len(hits)} finding(s)", hits, evidence=cfg["report"])


def check_trivy(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return missing(cid, cfg, cfg["report"])
    results = data.get("Results") or []
    if cfg.get("mode") == "evidence":
        counts: dict[str, int] = {}
        for res in results:
            for v in res.get("Vulnerabilities") or []:
                counts[v["Severity"]] = counts.get(v["Severity"], 0) + 1
        ranked = ", ".join(f"{k} {counts[k]}" for k in
                           ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] if k in counts)
        return CheckResult(cid, cfg["title"], "trivy", PASS,
                           f"Scanned {data.get('ArtifactName', 'artifact')}; "
                           f"risk-ranked: {ranked or 'no vulnerabilities'}",
                           evidence=cfg["report"])
    sev = set(cfg.get("severities", ["CRITICAL"]))
    classes = set(cfg.get("classes", []))
    hits = []
    for res in results:
        if classes and res.get("Class") not in classes:
            continue
        for v in res.get("Vulnerabilities") or []:
            if v["Severity"] not in sev:
                continue
            if cfg.get("fixable_only") and not v.get("FixedVersion"):
                continue
            hits.append(f'{v["VulnerabilityID"]} {v["PkgName"]} {v.get("InstalledVersion", "")}'
                        f' → fix {v.get("FixedVersion")}')
    return CheckResult(cid, cfg["title"], "trivy", verdict(cfg, bool(hits)),
                       f"{len(hits)} fixable {'/'.join(sorted(sev))} vulnerabilit(ies)",
                       sorted(set(hits)), evidence=cfg["report"])


def check_cyclonedx(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return missing(cid, cfg, cfg["report"])
    n = len(data.get("components") or [])
    ok = n >= cfg.get("min_components", 1)
    return CheckResult(cid, cfg["title"], "cyclonedx", verdict(cfg, not ok),
                       f"{n} components inventoried (spec {data.get('specVersion', '?')})",
                       evidence=cfg["report"])


def check_checkov(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return missing(cid, cfg, cfg["report"])
    blocks = data if isinstance(data, list) else [data]
    wanted = set(cfg["check_ids"])
    failed, passed, skipped = [], 0, []
    for b in blocks:
        res = b.get("results", {}) if isinstance(b, dict) else {}
        for f in res.get("failed_checks", []):
            if f["check_id"] in wanted:
                failed.append(f'{f["check_id"]} {f["resource"]} ({f["file_path"].lstrip("/")})')
        passed += sum(1 for p in res.get("passed_checks", []) if p["check_id"] in wanted)
        for s in res.get("skipped_checks", []):
            if s["check_id"] in wanted:
                skipped.append(f'{s["check_id"]} {s["resource"]}: '
                               f'{s.get("suppress_comment") or "no justification"}')
    if not failed and not passed and not skipped:
        return CheckResult(cid, cfg["title"], "checkov", NOT_RUN,
                           "No resources in scope for these checks", evidence=cfg["report"])
    summary = f"{passed} passed, {len(failed)} failed"
    if skipped:
        summary += f", {len(skipped)} accepted exception(s)"
    return CheckResult(cid, cfg["title"], "checkov", verdict(cfg, bool(failed)), summary,
                       failed, skipped, evidence=cfg["report"])


def check_zap(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return missing(cid, cfg, cfg["report"])
    fail_at, warn_at = cfg.get("fail_riskcode", 3), cfg.get("warn_riskcode", 2)
    worst, hits = 0, []
    names = {0: "Info", 1: "Low", 2: "Medium", 3: "High"}
    for site in data.get("site", []):
        for a in site.get("alerts", []):
            risk = int(a.get("riskcode", 0))
            if risk >= warn_at:
                worst = max(worst, risk)
                hits.append(f'[{names.get(risk, risk)}] {a.get("alert") or a.get("name")}'
                            f' (plugin {a.get("pluginid")}, {a.get("count", "?")} instance(s))')
    status = FAIL if worst >= fail_at else WARN if worst >= warn_at else PASS
    if status == FAIL and cfg.get("on_fail") == "warn":
        status = WARN
    return CheckResult(cid, cfg["title"], "zap", status,
                       f"{len(hits)} alert(s) at {names[warn_at]} or above", hits,
                       evidence=cfg["report"])


def check_github_reviews(cid, cfg, rdir):
    data = load_json(rdir / cfg["report"])
    if data is None:
        return CheckResult(cid, cfg["title"], "github", NOT_RUN,
                           "Not a pull-request build; enforced by branch protection",
                           evidence=cfg["report"])
    latest: dict[str, str] = {}
    for r in data:  # API returns reviews oldest first; keep each reviewer's latest state
        latest[r["user"]["login"]] = r["state"]
    approvers = sorted(u for u, s in latest.items() if s == "APPROVED")
    need = cfg.get("min_approvals", 1)
    return CheckResult(cid, cfg["title"], "github", verdict(cfg, len(approvers) < need),
                       f"{len(approvers)}/{need} approval(s)"
                       + (f": {', '.join(approvers)}" if approvers else ""),
                       evidence=cfg["report"])


def check_reports_present(cid, cfg, rdir):
    absent = [r for r in cfg["reports"] if not (rdir / r).is_file()]
    return CheckResult(cid, cfg["title"], "pipeline", verdict(cfg, bool(absent)),
                       f"{len(cfg['reports']) - len(absent)}/{len(cfg['reports'])} stage reports present",
                       [f"missing {r}" for r in absent])


PARSERS = {
    "gitleaks": check_gitleaks, "semgrep": check_semgrep, "trivy": check_trivy,
    "cyclonedx": check_cyclonedx, "checkov": check_checkov, "zap": check_zap,
    "github_reviews": check_github_reviews, "reports_present": check_reports_present,
}


# --------------------------------------------------------------------------- evaluate
def evaluate(config: dict, rdir: Path):
    checks = {}
    for cid, cfg in config["checks"].items():
        if cfg["tool"] not in PARSERS:
            raise SystemExit(f"Unknown tool '{cfg['tool']}' in check {cid}")
        checks[cid] = PARSERS[cfg["tool"]](cid, cfg, rdir)

    controls = []
    for c in config["controls"]:
        results = [checks[x] for x in c["checks"]]
        statuses = [r.status for r in results]
        if FAIL in statuses:
            status = FAIL
        elif WARN in statuses:
            status = WARN
        elif NOT_RUN in statuses:
            status = NOT_RUN
        else:
            status = PASS
        controls.append({**c, "status": status, "results": results})
    return checks, controls


def gate(controls, strict: bool):
    blockers = [c for c in controls if c.get("blocking", True)
                and (c["status"] == FAIL or (strict and c["status"] == NOT_RUN))]
    return blockers


# --------------------------------------------------------------------------- render
def run_context():
    sha = os.environ.get("GITHUB_SHA", "local")[:7]
    ref = os.environ.get("GITHUB_HEAD_REF") or os.environ.get("GITHUB_REF_NAME", "local")
    run = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run = (f'{os.environ.get("GITHUB_SERVER_URL", "https://github.com")}/'
               f'{os.environ.get("GITHUB_REPOSITORY")}/actions/runs/{os.environ["GITHUB_RUN_ID"]}')
    return {"commit": sha, "ref": ref, "run_url": run,
            "generated": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}


def md_escape(s: str) -> str:
    return s.replace("|", "\\|").replace("\n", " ")


def render_markdown(config, controls, blockers, ctx) -> str:
    out = []
    verdict_line = ("❌ **Compliance gate FAILED**: "
                    f"{len(blockers)} blocking control(s) not met" if blockers
                    else "✅ **Compliance gate PASSED**: all blocking controls have passing evidence")
    out.append("## Compliance evidence: PCI DSS & ISO 27001\n")
    out.append(f"{verdict_line}  \n")
    out.append(f"Commit `{ctx['commit']}` on `{ctx['ref']}` · {ctx['generated']}"
               + (f" · [pipeline run]({ctx['run_url']})" if ctx["run_url"] else "") + "\n")
    for fw_key, fw in config["frameworks"].items():
        rows = [c for c in controls if c["framework"] == fw_key]
        tally = {s: sum(1 for c in rows if c["status"] == s) for s in (PASS, FAIL, WARN, NOT_RUN)}
        out.append(f"\n### {fw['name']}  ·  {tally[PASS]} ✅ {tally[FAIL]} ❌ "
                   f"{tally[WARN]} ⚠️ {tally[NOT_RUN]} ⏭️\n")
        out.append("| Control | Requirement | Automated evidence | Result |")
        out.append("|---|---|---|---|")
        for c in rows:
            ev = "<br>".join(f"{ICON[r.status]} {md_escape(r.title)} "
                             f"<sub>({r.tool}: {md_escape(r.summary)})</sub>" for r in c["results"])
            gate_tag = "" if c.get("blocking", True) else " <sub>advisory</sub>"
            out.append(f"| **{c['id']}** | {md_escape(c['title'])} | {ev} | "
                       f"{ICON[c['status']]} {c['status']}{gate_tag} |")
    # findings
    seen, detail = set(), []
    for c in controls:
        for r in c["results"]:
            if r.check_id in seen or not (r.findings or r.exceptions):
                continue
            seen.add(r.check_id)
            lines = [f"- {md_escape(f)}" for f in r.findings[:MAX_FINDINGS]]
            if len(r.findings) > MAX_FINDINGS:
                lines.append(f"- … and {len(r.findings) - MAX_FINDINGS} more (see {r.evidence})")
            lines += [f"- 📝 accepted exception: {md_escape(e)}" for e in r.exceptions]
            detail.append(f"<details><summary>{ICON[r.status]} {r.title} "
                          f"({r.tool})</summary>\n\n" + "\n".join(lines) + "\n\n</details>")
    if detail:
        out.append("\n### Findings\n")
        out.extend(detail)
    out.append("\n<sub>Automated checks provide evidence for the controls listed; "
               "they do not by themselves establish compliance.</sub>\n")
    return "\n".join(out)


def render_html(config, controls, blockers, ctx) -> str:
    e = html.escape
    status_cls = {PASS: "pass", FAIL: "fail", WARN: "warn", NOT_RUN: "na"}
    label = {PASS: "Pass", FAIL: "Fail", WARN: "Warning", NOT_RUN: "Not run"}
    sections = []
    for fw_key, fw in config["frameworks"].items():
        rows = []
        for c in [c for c in controls if c["framework"] == fw_key]:
            ev = []
            for r in c["results"]:
                items = "".join(f"<li>{e(f)}</li>" for f in r.findings[:MAX_FINDINGS])
                items += "".join(f'<li class="exc">Accepted exception: {e(x)}</li>' for x in r.exceptions)
                ev.append(f'<div class="ev"><span class="dot {status_cls[r.status]}"></span>'
                          f'<div><div class="evt">{e(r.title)}</div>'
                          f'<div class="evs">{e(r.tool)} · {e(r.summary)}'
                          f'{" · " + e(r.evidence) if r.evidence else ""}</div>'
                          f'{"<ul>" + items + "</ul>" if items else ""}</div></div>')
            adv = '<span class="adv">advisory</span>' if not c.get("blocking", True) else ""
            rows.append(f'<tr><td class="cid">{e(c["id"])}</td><td>{e(c["title"])}</td>'
                        f'<td>{"".join(ev)}</td><td><span class="pill {status_cls[c["status"]]}">'
                        f'{label[c["status"]]}</span>{adv}</td></tr>')
        sections.append(f'<section><h2>{e(fw["name"])}</h2><div class="tw"><table><thead><tr>'
                        f'<th>Control</th><th>Requirement</th><th>Automated evidence</th>'
                        f'<th>Result</th></tr></thead><tbody>{"".join(rows)}</tbody></table></div></section>')
    banner_cls = "fail" if blockers else "pass"
    banner = (f"Gate failed: {len(blockers)} blocking control(s) not met ("
              + ", ".join(e(c["id"]) for c in blockers) + ")") if blockers \
        else "Gate passed: every blocking control has passing evidence"
    run = f' · <a href="{e(ctx["run_url"])}">pipeline run</a>' if ctx["run_url"] else ""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Compliance Evidence Matrix</title>
<style>
:root{{--bg:#f7f7f5;--card:#fff;--ink:#1d1d1b;--mute:#6b6b66;--line:#e4e3de;
--pass:#1f7a4d;--passbg:#e3f3ea;--fail:#b3261e;--failbg:#fbe5e3;--warn:#8a5a00;--warnbg:#fdf1d8;
--na:#5f6368;--nabg:#ececea}}
@media (prefers-color-scheme: dark){{:root{{--bg:#151514;--card:#1e1e1c;--ink:#ecebe6;--mute:#a19f98;
--line:#33322f;--passbg:#163626;--failbg:#3d1714;--warnbg:#3a2c0e;--nabg:#2a2a28;
--pass:#6fd39d;--fail:#ff8a80;--warn:#f2c46b;--na:#b0b0aa}}}}
*{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--ink);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}}
main{{max-width:1180px;margin:0 auto;padding:32px 16px 64px}}
h1{{font-size:26px;margin:0 0 4px}} .meta{{color:var(--mute);font-size:13px}}
.banner{{margin:20px 0 28px;padding:14px 18px;border-radius:10px;font-weight:600}}
.banner.pass{{background:var(--passbg);color:var(--pass)}} .banner.fail{{background:var(--failbg);color:var(--fail)}}
h2{{font-size:18px;margin:32px 0 10px}} .tw{{overflow-x:auto;background:var(--card);
border:1px solid var(--line);border-radius:10px}}
table{{border-collapse:collapse;width:100%;min-width:720px}}
th,td{{text-align:left;vertical-align:top;padding:12px 14px;border-bottom:1px solid var(--line)}}
th{{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--mute)}}
tr:last-child td{{border-bottom:0}} .cid{{font-weight:700;white-space:nowrap;font-variant-numeric:tabular-nums}}
.ev{{display:flex;gap:10px;margin-bottom:8px}} .ev:last-child{{margin-bottom:0}}
.dot{{flex:none;width:9px;height:9px;border-radius:50%;margin-top:7px}}
.dot.pass{{background:var(--pass)}}.dot.fail{{background:var(--fail)}}.dot.warn{{background:var(--warn)}}.dot.na{{background:var(--na)}}
.evt{{font-weight:500}} .evs{{color:var(--mute);font-size:13px}}
ul{{margin:4px 0 0;padding-left:18px;font:12.5px/1.5 ui-monospace,Menlo,Consolas,monospace}}
li.exc{{color:var(--warn);font-family:inherit}}
.pill{{display:inline-block;padding:2px 10px;border-radius:999px;font-size:12.5px;font-weight:600;white-space:nowrap}}
.pill.pass{{background:var(--passbg);color:var(--pass)}}.pill.fail{{background:var(--failbg);color:var(--fail)}}
.pill.warn{{background:var(--warnbg);color:var(--warn)}}.pill.na{{background:var(--nabg);color:var(--na)}}
.adv{{display:block;color:var(--mute);font-size:12px;margin-top:4px}}
footer{{margin-top:28px;color:var(--mute);font-size:13px}} a{{color:inherit}}
</style></head><body><main>
<h1>Compliance evidence matrix</h1>
<div class="meta">Commit {e(ctx['commit'])} on {e(ctx['ref'])} · generated {e(ctx['generated'])}{run}</div>
<div class="banner {banner_cls}">{banner}</div>
{''.join(sections)}
<footer>Automated checks provide evidence for the listed controls; they do not by themselves
establish PCI DSS or ISO/IEC 27001 compliance. Raw scanner reports are attached to the pipeline run.</footer>
</main></body></html>"""


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", default=str(Path(__file__).with_name("controls.yaml")))
    ap.add_argument("--reports-dir", default="reports")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--strict", action="store_true",
                    help="also fail when a blocking control has no evidence")
    args = ap.parse_args(argv)

    config = yaml.safe_load(Path(args.config).read_text(encoding="utf-8"))
    rdir = Path(args.reports_dir)
    odir = Path(args.out_dir or args.reports_dir)
    odir.mkdir(parents=True, exist_ok=True)

    checks, controls = evaluate(config, rdir)
    blockers = gate(controls, args.strict)
    ctx = run_context()

    md = render_markdown(config, controls, blockers, ctx)
    (odir / "compliance-matrix.md").write_text(md, encoding="utf-8")
    (odir / "compliance-matrix.html").write_text(render_html(config, controls, blockers, ctx),
                                                 encoding="utf-8")
    (odir / "compliance-results.json").write_text(json.dumps({
        "context": ctx,
        "gate": "FAIL" if blockers else "PASS",
        "blocking_failures": [f'{c["framework"]}:{c["id"]}' for c in blockers],
        "controls": [{"framework": c["framework"], "id": c["id"], "title": c["title"],
                      "status": c["status"], "blocking": c.get("blocking", True),
                      "checks": [r.check_id for r in c["results"]]} for c in controls],
        "checks": {k: vars(v) for k, v in checks.items()},
    }, indent=2), encoding="utf-8")

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a", encoding="utf-8") as fh:
            fh.write(md + "\n")

    for fw_key, fw in config["frameworks"].items():
        print(f"\n{fw['name']}")
        for c in [c for c in controls if c["framework"] == fw_key]:
            print(f"  {c['status']:<8} {c['id']:<7} {c['title']}")
    print(f"\nGate: {'FAIL' if blockers else 'PASS'}"
          + (f" ({', '.join(c['framework'] + ':' + c['id'] for c in blockers)})" if blockers else ""))
    return 1 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
