#!/usr/bin/env bash
# Runs the same security stages as the CI pipeline on your laptop (Docker only),
# then builds the compliance matrix in reports/compliance-matrix.html.
#
#   ./scripts/run-local.sh            # all stages
#   SKIP_DAST=1 ./scripts/run-local.sh  # skip the ZAP scan (fastest)
set -euo pipefail
cd "$(dirname "$0")/.."

GITLEAKS_IMAGE=zricethezav/gitleaks:v8.21.2
SEMGREP_IMAGE=semgrep/semgrep:1.182.1
CHECKOV_IMAGE=bridgecrew/checkov:3.3.30
TRIVY_IMAGE=aquasec/trivy:0.69.3
ZAP_IMAGE=ghcr.io/zaproxy/zaproxy:stable
MAVEN_IMAGE=maven:3.9-eclipse-temurin-21
IMAGE=payments-api:local

step() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }

rm -rf reports && mkdir -p reports && chmod a+rwx reports

step "Secrets scan (Gitleaks) — PCI 8.6.2 / ISO A.5.17"
docker run --rm -v "$PWD:/repo" -w /repo "$GITLEAKS_IMAGE" \
  dir . --config .gitleaks.toml --redact --report-format json \
  --report-path reports/gitleaks.json --exit-code 0

step "SAST (Semgrep) — PCI 6.2.4, 3.5.1 / ISO A.8.28, A.8.24"
docker run --rm -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
  semgrep scan --config .semgrep/ --metrics=off --exclude demo-kit --exclude compliance \
  --json -o reports/semgrep.json .

step "IaC + Dockerfile (Checkov) — PCI 1.3.1, 2.2.6, 3.5.1, 4.2.1, 6.4.2, 10.2.1"
docker run --rm -v "$PWD:/src" -w /src "$CHECKOV_IMAGE" \
  -d . --framework terraform dockerfile --skip-path demo-kit -o json --soft-fail \
  > reports/checkov.json

step "Build + SBOM (Maven, CycloneDX) — PCI 6.3.2 / ISO A.5.9"
docker run --rm -v "$PWD/app:/app" -v "$HOME/.m2:/root/.m2" -w /app "$MAVEN_IMAGE" \
  mvn -B -ntp verify
cp app/target/bom.json reports/bom.json
docker build -t "$IMAGE" app

step "Image scan (Trivy) — PCI 6.3.1, 6.3.3 / ISO A.8.8"
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v "$PWD/reports:/out" \
  "$TRIVY_IMAGE" image --scanners vuln --pkg-types os,library \
  --format json --output /out/trivy-image.json "$IMAGE"

if [[ "${SKIP_DAST:-0}" != "1" ]]; then
  step "DAST baseline (ZAP) — PCI 6.4.1 / ISO A.8.29"
  docker rm -f payments-dast >/dev/null 2>&1 || true
  docker run -d --name payments-dast -p 8080:8080 \
    -e CARD_FINGERPRINT_KEY="$(openssl rand -hex 32)" "$IMAGE" >/dev/null
  for _ in $(seq 1 60); do curl -fs http://localhost:8080/actuator/health >/dev/null && break; sleep 2; done
  docker run --rm --add-host=host.docker.internal:host-gateway \
    -v "$PWD/reports:/zap/wrk:rw" "$ZAP_IMAGE" \
    zap-baseline.py -t "http://host.docker.internal:8080/api/v1/cards?customerId=cust-001" \
    -J zap.json -I || true
  docker rm -f payments-dast >/dev/null
fi

step "Compliance gate"
python3 -c "import yaml" 2>/dev/null || pip3 install --quiet pyyaml
set +e
python3 compliance/aggregate.py --reports-dir reports
code=$?
set -e
echo
echo "Matrix: reports/compliance-matrix.html  (markdown: reports/compliance-matrix.md)"
exit $code
