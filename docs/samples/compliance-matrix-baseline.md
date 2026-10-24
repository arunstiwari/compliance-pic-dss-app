## Compliance evidence: PCI DSS & ISO 27001

❌ **Compliance gate FAILED**: 16 blocking control(s) not met  

Commit `local` on `local` · 2026-10-24 17:03 UTC


### PCI DSS v4.0.1  ·  2 ✅ 9 ❌ 1 ⚠️ 1 ⏭️

| Control | Requirement | Automated evidence | Result |
|---|---|---|---|
| **1.3.1** | Inbound traffic to the CDE is restricted | ❌ No admin ports open to the internet <sub>(checkov: 5 passed, 1 failed)</sub> | ❌ FAIL |
| **2.2.6** | System security parameters configured to prevent misuse | ❌ Container image hardened (pinned base, non-root, healthcheck) <sub>(checkov: 0 passed, 3 failed)</sub> | ❌ FAIL |
| **3.5.1** | PAN rendered unreadable wherever it is stored | ❌ Storage encrypted at rest (S3 KMS, RDS) <sub>(checkov: 0 passed, 2 failed)</sub><br>❌ No weak hashing of sensitive data <sub>(semgrep: 1 finding(s))</sub> | ❌ FAIL |
| **4.2.1** | Strong cryptography protects PAN in transit over public networks | ❌ HTTPS with TLS 1.2+ on public endpoints <sub>(checkov: 0 passed, 2 failed)</sub> | ❌ FAIL |
| **6.2.3** | Bespoke software reviewed before release to production | ⏭️ Change peer-reviewed and approved before merge <sub>(github: Not a pull-request build; enforced by branch protection)</sub> | ⏭️ NOT_RUN <sub>advisory</sub> |
| **6.2.4** | Engineering techniques prevent common software attacks | ❌ No injection flaws (SQLi, expression/template injection) <sub>(semgrep: 2 finding(s))</sub> | ❌ FAIL |
| **6.3.1** | Security vulnerabilities identified and risk-ranked | ✅ Image and dependency vulnerability scan performed and risk-ranked <sub>(trivy: Scanned payments-api:ci; risk-ranked: CRITICAL 1, HIGH 1, MEDIUM 1)</sub> | ✅ PASS |
| **6.3.2** | Inventory of bespoke and third-party software components | ✅ SBOM (CycloneDX) generated for the build <sub>(cyclonedx: 6 components inventoried (spec 1.6))</sub> | ✅ PASS |
| **6.3.3** | Critical security patches installed promptly | ❌ No fixable CRITICAL vulnerabilities in application dependencies <sub>(trivy: 1 fixable CRITICAL vulnerabilit(ies))</sub><br>✅ No fixable CRITICAL vulnerabilities in base-image OS packages <sub>(trivy: 0 fixable CRITICAL vulnerabilit(ies))</sub> | ❌ FAIL |
| **6.4.1** | Public-facing web apps assessed for vulnerabilities | ⚠️ DAST baseline scan of the running app <sub>(zap: 1 alert(s) at Medium or above)</sub> | ⚠️ WARN |
| **6.4.2** | Automated solution detects/prevents attacks on public web apps | ❌ Public load balancer protected by a WAF <sub>(checkov: 0 passed, 1 failed)</sub> | ❌ FAIL |
| **8.6.2** | Application/system account credentials not hard-coded | ❌ No secrets committed to source <sub>(gitleaks: 1 secret(s) detected)</sub> | ❌ FAIL |
| **10.2.1** | Audit logs enabled and active | ❌ Access and audit logging enabled (S3, ALB, RDS) <sub>(checkov: 0 passed, 3 failed)</sub> | ❌ FAIL |

### ISO/IEC 27001:2022 Annex A  ·  2 ✅ 7 ❌ 1 ⚠️ 1 ⏭️

| Control | Requirement | Automated evidence | Result |
|---|---|---|---|
| **A.5.9** | Inventory of information and other associated assets | ✅ SBOM (CycloneDX) generated for the build <sub>(cyclonedx: 6 components inventoried (spec 1.6))</sub> | ✅ PASS |
| **A.5.17** | Authentication information | ❌ No secrets committed to source <sub>(gitleaks: 1 secret(s) detected)</sub> | ❌ FAIL |
| **A.8.8** | Management of technical vulnerabilities | ❌ No fixable CRITICAL vulnerabilities in application dependencies <sub>(trivy: 1 fixable CRITICAL vulnerabilit(ies))</sub><br>✅ No fixable CRITICAL vulnerabilities in base-image OS packages <sub>(trivy: 0 fixable CRITICAL vulnerabilit(ies))</sub> | ❌ FAIL |
| **A.8.9** | Configuration management | ❌ Container image hardened (pinned base, non-root, healthcheck) <sub>(checkov: 0 passed, 3 failed)</sub> | ❌ FAIL |
| **A.8.15** | Logging | ❌ Access and audit logging enabled (S3, ALB, RDS) <sub>(checkov: 0 passed, 3 failed)</sub> | ❌ FAIL |
| **A.8.20** | Networks security | ❌ No admin ports open to the internet <sub>(checkov: 5 passed, 1 failed)</sub><br>❌ Public load balancer protected by a WAF <sub>(checkov: 0 passed, 1 failed)</sub> | ❌ FAIL |
| **A.8.24** | Use of cryptography | ❌ Storage encrypted at rest (S3 KMS, RDS) <sub>(checkov: 0 passed, 2 failed)</sub><br>❌ HTTPS with TLS 1.2+ on public endpoints <sub>(checkov: 0 passed, 2 failed)</sub><br>❌ No weak hashing of sensitive data <sub>(semgrep: 1 finding(s))</sub> | ❌ FAIL |
| **A.8.25** | Secure development life cycle | ✅ All security stages ran and produced evidence <sub>(pipeline: 6/6 stage reports present)</sub> | ✅ PASS |
| **A.8.28** | Secure coding | ❌ No injection flaws (SQLi, expression/template injection) <sub>(semgrep: 2 finding(s))</sub><br>❌ No weak hashing of sensitive data <sub>(semgrep: 1 finding(s))</sub> | ❌ FAIL |
| **A.8.29** | Security testing in development and acceptance | ⚠️ DAST baseline scan of the running app <sub>(zap: 1 alert(s) at Medium or above)</sub> | ⚠️ WARN |
| **A.8.32** | Change management | ⏭️ Change peer-reviewed and approved before merge <sub>(github: Not a pull-request build; enforced by branch protection)</sub> | ⏭️ NOT_RUN <sub>advisory</sub> |

### Findings

<details><summary>❌ No admin ports open to the internet (checkov)</summary>

- CKV_AWS_24 aws_security_group.api (infra/terraform/main.tf)

</details>
<details><summary>❌ Container image hardened (pinned base, non-root, healthcheck) (checkov)</summary>

- CKV_DOCKER_7 /app/Dockerfile.FROM (app/Dockerfile)
- CKV_DOCKER_2 /app/Dockerfile. (app/Dockerfile)
- CKV_DOCKER_3 /app/Dockerfile. (app/Dockerfile)

</details>
<details><summary>❌ Storage encrypted at rest (S3 KMS, RDS) (checkov)</summary>

- CKV_AWS_16 aws_db_instance.payments (infra/terraform/main.tf)
- CKV_AWS_145 aws_s3_bucket.card_exports (infra/terraform/main.tf)

</details>
<details><summary>❌ No weak hashing of sensitive data (semgrep)</summary>

- weak-hash-algorithm at app/src/main/java/com/demo/payments/security/CardFingerprint.java:17

</details>
<details><summary>❌ HTTPS with TLS 1.2+ on public endpoints (checkov)</summary>

- CKV_AWS_2 aws_lb_listener.api (infra/terraform/main.tf)
- CKV_AWS_103 aws_lb_listener.api (infra/terraform/main.tf)

</details>
<details><summary>❌ No injection flaws (SQLi, expression/template injection) (semgrep)</summary>

- jdbc-sql-string-concat at app/src/main/java/com/demo/payments/web/CardController.java:26
- commons-text-interpolator-on-input at app/src/main/java/com/demo/payments/web/ReceiptController.java:18

</details>
<details><summary>❌ No fixable CRITICAL vulnerabilities in application dependencies (trivy)</summary>

- CVE-2022-42889 org.apache.commons:commons-text 1.9 → fix 1.10.0

</details>
<details><summary>⚠️ DAST baseline scan of the running app (zap)</summary>

- [Medium] Content Security Policy (CSP) Header Not Set (plugin 10038, 3 instance(s))

</details>
<details><summary>❌ Public load balancer protected by a WAF (checkov)</summary>

- CKV2_AWS_28 aws_lb.api (infra/terraform/main.tf)

</details>
<details><summary>❌ No secrets committed to source (gitleaks)</summary>

- paygate-live-api-key in app/src/main/java/com/demo/payments/config/PaymentGatewayConfig.java:14

</details>
<details><summary>❌ Access and audit logging enabled (S3, ALB, RDS) (checkov)</summary>

- CKV_AWS_129 aws_db_instance.payments (infra/terraform/main.tf)
- CKV_AWS_91 aws_lb.api (infra/terraform/main.tf)
- CKV_AWS_18 aws_s3_bucket.card_exports (infra/terraform/main.tf)

</details>

<sub>Automated checks provide evidence for the controls listed; they do not by themselves establish compliance.</sub>
