# Fixtures

The files in this directory are **broken on purpose**. `self-test.yml` uses them
to prove each scanner really finds something, and that those findings disappear
when the review is unplugged.

Do not fix them. The credentials here are fake and were never valid.

| File | Triggers | Expected severity |
|---|---|---|
| `leaked_key.py` | Gitleaks | Critical |
| `sqli.py` | Semgrep `p/ci` | High / Medium |
| `requirements.txt` | Trivy | from the CVE's own CVSS score |
