# Controls-as-Code DevSecOps Demo: PCI DSS & ISO 27001

A Spring Boot card-payments API with deliberately planted security issues, and a
GitHub Actions pipeline that maps every automated security check to
**PCI DSS v4.0.1** and **ISO/IEC 27001:2022 Annex A** controls. Each build produces a
control-by-control compliance matrix: in the job summary, as a PR comment, and as an
HTML evidence page. The build is blocked when a blocking control fails.

```
PR opened ──► Gitleaks ─┐
          ├─► Semgrep  ─┤
          ├─► Checkov  ─┼─► compliance/aggregate.py ──► matrix (summary + PR comment + HTML)
          └─► Maven ► SBOM ► Trivy ► ZAP ─┘     │           evidence bundle (90 days)
                                                └─► exit 1 if a blocking control fails
main ──► signed image (Cosign keyless) + SBOM attestation
```

## Repository layout

| Path | What it is |
|---|---|
| `app/` | Spring Boot 4 payments API (Java 21) **with planted issues**; `Dockerfile` |
| `infra/terraform/main.tf` | AWS footprint with planted misconfigurations (scanned statically, never applied) |
| `compliance/controls.yaml` | **The mapping**: checks → PCI DSS / ISO 27001 controls, blocking or advisory |
| `compliance/aggregate.py` | Reads scanner reports + mapping, writes matrix (MD/HTML/JSON), gates the build |
| `compliance/tests/` | Unit tests + fixtures (real Gitleaks/Semgrep/Checkov output for both states) |
| `.github/workflows/devsecops.yml` | The pipeline |
| `.semgrep/payments-rules.yml` | SAST rules (SQLi, Text4Shell pattern, weak hashing) |
| `.gitleaks.toml` | Default Gitleaks rules + one for the fictional "PayGate" key |
| `demo-kit/fixes/` + `apply-fixes.sh` | Remediated versions of every file; creates the "fix" PR |
| `scripts/run-local.sh` | Same stages on a laptop, Docker only |
| `docs/samples/` | Example matrices (baseline and fixed) to preview before running anything |

## Planted issues and the controls they break

| Planted issue | Detected by | PCI DSS v4.0.1 | ISO 27001:2022 |
|---|---|---|---|
| SQL built by string concatenation | Semgrep | 6.2.4 | A.8.28 |
| `StringSubstitutor.createInterpolator()` on user input | Semgrep | 6.2.4 | A.8.28 |
| Unkeyed MD5 of the PAN | Semgrep | 3.5.1 | A.8.24, A.8.28 |
| Hard-coded live API key | Gitleaks | 8.6.2 | A.5.17 |
| `commons-text 1.9` (CVE-2022-42889, CRITICAL) | Trivy | 6.3.3 | A.8.8 |
| Dockerfile: `latest` tag, runs as root, no healthcheck | Checkov | 2.2.6 | A.8.9 |
| S3 bucket without KMS, RDS unencrypted | Checkov | 3.5.1 | A.8.24 |
| ALB on plain HTTP | Checkov | 4.2.1 | A.8.24 |
| No S3/ALB/RDS logging | Checkov | 10.2.1 | A.8.15 |
| SSH open to 0.0.0.0/0 | Checkov | 1.3.1 | A.8.20 |
| No WAF in front of the public ALB | Checkov | 6.4.2 | A.8.20 |
| Missing security headers | ZAP baseline | 6.4.1 | A.8.29 |

Always-on evidence rows: SBOM (PCI 6.3.2, A.5.9), risk-ranked vulnerability scan
(PCI 6.3.1), all stages produced reports (A.8.25), PR approved (PCI 6.2.3, A.8.32;
advisory, because branch protection enforces it).

## Setup (about 10 minutes)

1. Create a GitHub repo and push this folder to `main`.
2. **Settings → Branches → Add rule for `main`:** require a pull request with 1 approval,
   and require the status check **"Compliance gate (PCI DSS + ISO 27001)"**.
   (Run the workflow once first so the check name appears in the list.)
3. Keep the default read-only workflow token; each job requests the permissions it
   needs. If your org restricts Actions from commenting on PRs, allow it, or the matrix
   will only appear in the job summary.
4. Before the demo, bump `spring-boot-starter-parent` in `app/pom.xml` and
   `demo-kit/fixes/app/pom.xml` to the newest 4.0.x/4.1.x patch so the framework itself
   scans clean, and do a dry run of both acts.

## Running the demo

**Act 1: the red build.** Make any small change on a branch (for example, edit this
README), open a PR, and let the pipeline run. The gate fails, and the PR comment shows
a matrix like `docs/samples/compliance-matrix-baseline.html`: 9 PCI and 7 ISO blocking
controls red (plus the advisory review rows), each with the exact file, line, resource or CVE as evidence. Merging is blocked.

Talking points:
- One finding lights up rows in **both** frameworks (the hard-coded key fails PCI 8.6.2 and ISO A.5.17).
- Open a failed row: the evidence names the tool, the rule or CVE, and the file. That is what a QSA or ISO auditor asks for.
- `controls.yaml` is code: reviewed in PRs, versioned, diffable. Changing a control's mapping is itself a controlled change.

**Act 2: the fix.**
```bash
git switch main && ./demo-kit/apply-fixes.sh
git push -u origin fix/compliance     # open a PR into main
```
The matrix turns green. The review rows (6.2.3 / A.8.32) show an advisory
*Fail* until a reviewer approves. Approve the PR and the pipeline re-runs (it listens for review
events), and those rows go green too.

Talking points:
- Checkov shows one **accepted exception**: the ALB log bucket uses SSE-S3 because AWS requires it. The justification and ticket number live in the code (`#checkov:skip=…`) and appear in the matrix, so exceptions are visible and auditable instead of silent.
- Removing the leaked key from code does not un-leak it. Git history still has it, so it must be rotated. This is why secrets scanning runs before merge.

**Act 3: the evidence.** Download the `compliance-evidence-<sha>` artifact. It
contains every raw report plus the HTML matrix and the exact `controls.yaml` used,
for every build. On `main`, the release job signs the image with Cosign and attaches
the SBOM as an attestation.

## Run locally

```bash
./scripts/run-local.sh              # needs Docker; writes reports/compliance-matrix.html
SKIP_DAST=1 ./scripts/run-local.sh  # skip ZAP
NO_GIT=1 ./demo-kit/apply-fixes.sh  # apply fixes without creating a branch, then re-run
python3 -m unittest discover -s compliance/tests   # gate logic tests (needs pyyaml)
```

## Adding a control

1. Add (or reuse) a check under `checks:` in `compliance/controls.yaml`.
   Supported tools: `gitleaks`, `semgrep` (filter by `rules`), `trivy`
   (`severities`, `classes`, `fixable_only`, or `mode: evidence`), `checkov`
   (`check_ids`), `cyclonedx`, `zap` (`fail_riskcode`/`warn_riskcode`),
   `github_reviews`, `reports_present`. Use `on_fail: warn` for non-blocking checks.
2. Add the control under `controls:` with its framework, id, title, checks and `blocking`.

Example: to cover ISO A.8.12 (data leakage prevention) with the existing secrets
scan, add a control with `checks: [secrets-scan]`.

## Caveats to state in the demo

- An automated check is **evidence for** a control, not compliance with it. Most
  PCI DSS and ISO 27001 requirements also have process, policy and people parts that
  no pipeline can show. The matrix footer says this.
- The control wording in `controls.yaml` is abbreviated. Check requirement text and
  numbering against the official PCI DSS v4.0.1 and ISO/IEC 27001:2022 documents
  before showing this to auditors.
- The fixed Terraform still has unmapped Checkov findings (Multi-AZ, versioning,
  replication, and so on). The gate looks only at mapped check IDs. The full Checkov
  report is in the evidence bundle.
- Pin actions and images to commit SHAs / digests for real use. The workflow pins
  Trivy to an image tag outside the range affected by the March 2026 trivy-action
  compromise (CVE-2026-33634).
