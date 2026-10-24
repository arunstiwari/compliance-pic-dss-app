## Compliance evidence: PCI DSS & ISO 27001

✅ **Compliance gate PASSED**: all blocking controls have passing evidence  

Commit `local` on `local` · 2026-10-24 17:03 UTC


### PCI DSS v4.0.1  ·  13 ✅ 0 ❌ 0 ⚠️ 0 ⏭️

| Control | Requirement | Automated evidence | Result |
|---|---|---|---|
| **1.3.1** | Inbound traffic to the CDE is restricted | ✅ No admin ports open to the internet <sub>(checkov: 6 passed, 0 failed)</sub> | ✅ PASS |
| **2.2.6** | System security parameters configured to prevent misuse | ✅ Container image hardened (pinned base, non-root, healthcheck) <sub>(checkov: 3 passed, 0 failed)</sub> | ✅ PASS |
| **3.5.1** | PAN rendered unreadable wherever it is stored | ✅ Storage encrypted at rest (S3 KMS, RDS) <sub>(checkov: 2 passed, 0 failed, 1 accepted exception(s))</sub><br>✅ No weak hashing of sensitive data <sub>(semgrep: 0 finding(s))</sub> | ✅ PASS |
| **4.2.1** | Strong cryptography protects PAN in transit over public networks | ✅ HTTPS with TLS 1.2+ on public endpoints <sub>(checkov: 2 passed, 0 failed)</sub> | ✅ PASS |
| **6.2.3** | Bespoke software reviewed before release to production | ✅ Change peer-reviewed and approved before merge <sub>(github: 1/1 approval(s): security-lead)</sub> | ✅ PASS <sub>advisory</sub> |
| **6.2.4** | Engineering techniques prevent common software attacks | ✅ No injection flaws (SQLi, expression/template injection) <sub>(semgrep: 0 finding(s))</sub> | ✅ PASS |
| **6.3.1** | Security vulnerabilities identified and risk-ranked | ✅ Image and dependency vulnerability scan performed and risk-ranked <sub>(trivy: Scanned payments-api:ci; risk-ranked: no vulnerabilities)</sub> | ✅ PASS |
| **6.3.2** | Inventory of bespoke and third-party software components | ✅ SBOM (CycloneDX) generated for the build <sub>(cyclonedx: 6 components inventoried (spec 1.6))</sub> | ✅ PASS |
| **6.3.3** | Critical security patches installed promptly | ✅ No fixable CRITICAL vulnerabilities in application dependencies <sub>(trivy: 0 fixable CRITICAL vulnerabilit(ies))</sub><br>✅ No fixable CRITICAL vulnerabilities in base-image OS packages <sub>(trivy: 0 fixable CRITICAL vulnerabilit(ies))</sub> | ✅ PASS |
| **6.4.1** | Public-facing web apps assessed for vulnerabilities | ✅ DAST baseline scan of the running app <sub>(zap: 0 alert(s) at Medium or above)</sub> | ✅ PASS |
| **6.4.2** | Automated solution detects/prevents attacks on public web apps | ✅ Public load balancer protected by a WAF <sub>(checkov: 1 passed, 0 failed)</sub> | ✅ PASS |
| **8.6.2** | Application/system account credentials not hard-coded | ✅ No secrets committed to source <sub>(gitleaks: 0 secret(s) detected)</sub> | ✅ PASS |
| **10.2.1** | Audit logs enabled and active | ✅ Access and audit logging enabled (S3, ALB, RDS) <sub>(checkov: 4 passed, 0 failed)</sub> | ✅ PASS |

### ISO/IEC 27001:2022 Annex A  ·  11 ✅ 0 ❌ 0 ⚠️ 0 ⏭️

| Control | Requirement | Automated evidence | Result |
|---|---|---|---|
| **A.5.9** | Inventory of information and other associated assets | ✅ SBOM (CycloneDX) generated for the build <sub>(cyclonedx: 6 components inventoried (spec 1.6))</sub> | ✅ PASS |
| **A.5.17** | Authentication information | ✅ No secrets committed to source <sub>(gitleaks: 0 secret(s) detected)</sub> | ✅ PASS |
| **A.8.8** | Management of technical vulnerabilities | ✅ No fixable CRITICAL vulnerabilities in application dependencies <sub>(trivy: 0 fixable CRITICAL vulnerabilit(ies))</sub><br>✅ No fixable CRITICAL vulnerabilities in base-image OS packages <sub>(trivy: 0 fixable CRITICAL vulnerabilit(ies))</sub> | ✅ PASS |
| **A.8.9** | Configuration management | ✅ Container image hardened (pinned base, non-root, healthcheck) <sub>(checkov: 3 passed, 0 failed)</sub> | ✅ PASS |
| **A.8.15** | Logging | ✅ Access and audit logging enabled (S3, ALB, RDS) <sub>(checkov: 4 passed, 0 failed)</sub> | ✅ PASS |
| **A.8.20** | Networks security | ✅ No admin ports open to the internet <sub>(checkov: 6 passed, 0 failed)</sub><br>✅ Public load balancer protected by a WAF <sub>(checkov: 1 passed, 0 failed)</sub> | ✅ PASS |
| **A.8.24** | Use of cryptography | ✅ Storage encrypted at rest (S3 KMS, RDS) <sub>(checkov: 2 passed, 0 failed, 1 accepted exception(s))</sub><br>✅ HTTPS with TLS 1.2+ on public endpoints <sub>(checkov: 2 passed, 0 failed)</sub><br>✅ No weak hashing of sensitive data <sub>(semgrep: 0 finding(s))</sub> | ✅ PASS |
| **A.8.25** | Secure development life cycle | ✅ All security stages ran and produced evidence <sub>(pipeline: 6/6 stage reports present)</sub> | ✅ PASS |
| **A.8.28** | Secure coding | ✅ No injection flaws (SQLi, expression/template injection) <sub>(semgrep: 0 finding(s))</sub><br>✅ No weak hashing of sensitive data <sub>(semgrep: 0 finding(s))</sub> | ✅ PASS |
| **A.8.29** | Security testing in development and acceptance | ✅ DAST baseline scan of the running app <sub>(zap: 0 alert(s) at Medium or above)</sub> | ✅ PASS |
| **A.8.32** | Change management | ✅ Change peer-reviewed and approved before merge <sub>(github: 1/1 approval(s): security-lead)</sub> | ✅ PASS <sub>advisory</sub> |

### Findings

<details><summary>✅ Storage encrypted at rest (S3 KMS, RDS) (checkov)</summary>

- 📝 accepted exception: CKV_AWS_145 aws_s3_bucket.access_logs: no justification

</details>

<sub>Automated checks provide evidence for the controls listed; they do not by themselves establish compliance.</sub>
