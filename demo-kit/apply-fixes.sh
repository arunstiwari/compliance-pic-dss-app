#!/usr/bin/env bash
# Demo act 2: creates a branch that remediates every planted issue, so the PR's
# compliance matrix turns green.
#
#   ./demo-kit/apply-fixes.sh            # creates branch fix/compliance and commits
#   NO_GIT=1 ./demo-kit/apply-fixes.sh   # just copy the files (local runs)
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ "${NO_GIT:-0}" != "1" ]]; then
  git switch -c fix/compliance
fi

cp -R demo-kit/fixes/. .
echo "Applied fixes:"
(cd demo-kit/fixes && find . -type f | sed 's#^\./#  #' | sort)

if [[ "${NO_GIT:-0}" != "1" ]]; then
  git add -A app infra
  git commit -m "Remediate PCI DSS / ISO 27001 findings

- Parameterised SQL and allow-listed template substitution (PCI 6.2.4, A.8.28)
- Secret moved to environment / secrets manager (PCI 8.6.2, A.5.17)
- HMAC-SHA256 card fingerprint (PCI 3.5.1, A.8.24)
- commons-text 1.14.0 (PCI 6.3.3, A.8.8)
- Hardened container image (PCI 2.2.6, A.8.9)
- KMS encryption, TLS 1.2+, logging, WAF, restricted SSH (PCI 1.3.1/3.5.1/4.2.1/6.4.2/10.2.1)"
  echo
  echo "Next: git push -u origin fix/compliance  and open a PR into main."
  echo "Reminder: rotate the leaked PayGate key. Removing it from code does not un-leak it."
fi
