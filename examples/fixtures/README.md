# Fixtures

File di direktori ini **sengaja bermasalah**. Ia dipakai `self-test.yml` untuk
membuktikan tiap scanner benar-benar menemukan sesuatu, dan bahwa temuan itu
hilang saat review-nya dicopot.

Jangan diperbaiki. Kredensial di sini palsu dan tidak pernah valid.

| File | Memicu | Severity yang diharapkan |
|---|---|---|
| `leaked_key.py` | Gitleaks | Critical |
| `sqli.py` | Semgrep `p/ci` | High / Medium |
| `requirements.txt` | Trivy | dari skor CVSS asli CVE-nya |
