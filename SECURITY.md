# Security Policy

## Project scope

CyberShield AI is a **defensive cybersecurity intelligence tool**. It fetches publicly available vulnerability metadata from the NVD CVE API and the CISA Known Exploited Vulnerabilities (KEV) catalogue, scores risk, and provides defensive remediation guidance to help security teams prioritise patching.

This project does **not**:
- Provide exploit code, proof-of-concept attack scripts, or attack instructions.
- Perform offensive scanning, probing, or active enumeration of any systems.
- Store or transmit personal data, credentials, or proprietary information.
- Download or bundle full vulnerability databases locally.

---

## Supported versions

This project is currently in its initial release phase. Only the latest commit on the `main` branch is actively maintained.

| Version | Supported |
|---|---|
| `main` (latest) | ✅ Active |
| Older commits | No backports |

---

## Reporting a security issue

**Please do not report security vulnerabilities through public GitHub Issues.**

If you discover a security vulnerability in this project — for example, a dependency with a known CVE, an accidental secret committed in history, or a logic flaw that could be abused — please report it privately:

**Email:** imnazishatta@gmail.com

Include in your report:
- A clear description of the issue.
- The file(s) or dependency affected.
- Steps to reproduce the issue (if applicable).
- Your assessment of severity and impact.
- Whether the issue involves any real credentials or personally identifiable information.

You will receive an acknowledgement within **5 business days**. We aim to resolve confirmed issues within **30 days** of acknowledgement, or faster if the severity warrants it.

---

## What to include — and what not to include

**Include:**
- A description of the vulnerability and its potential impact.
- Affected file paths, function names, or dependency versions.
- A minimal reproduction case if the issue is a code bug.

**Do not include:**
- Real API keys, tokens, passwords, or credentials — even as examples.
- Actual exploit code or working attack payloads.
- Sensitive details about live systems or organisations you have tested.

---

## Responsible disclosure expectations

We follow a responsible disclosure process:

1. You report the issue privately via email.
2. We acknowledge receipt within 5 business days.
3. We investigate and, if confirmed, develop a fix.
4. We release the fix and publicly credit the reporter (unless you prefer to remain anonymous).
5. You may disclose the issue publicly after the fix is released, or after 90 days — whichever comes first.

We ask that you do not disclose the issue publicly before a fix is available, unless we have not responded within 30 days.

---

## Dependencies

This project uses pinned dependencies listed in `requirements.txt`. If you discover that a dependency has a known CVE, please open a private report as described above. We will update the dependency pin promptly.

---

## Secrets and credentials policy

- **`.env` is git-ignored** — never commit it.
- API keys must be stored in `.env` and never committed to version control.
- The GitHub Actions CI workflow includes an automated secret hygiene scan on every push.
- If a secret is accidentally committed, treat it as compromised immediately: revoke it at the issuing service, then remove it from git history.

---

## Statement on exploit content

This project does not provide, generate, or assist in generating exploit code, attack steps, or offensive techniques — either directly or through AI-assisted means. All risk scores, recommendations, and API responses are oriented toward **defensive actions** (patching, isolation, compensating controls).

Any contribution, issue, or pull request that attempts to introduce exploit content will be closed without merge and reported if necessary.

---

## Contact

Security reports: **imnazishatta@gmail.com**

General questions: [GitHub Issues](https://github.com/nazishatta/CyberShield-AI-Threat-Risk-Intelligence/issues)
