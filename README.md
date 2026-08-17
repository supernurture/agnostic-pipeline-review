# Agnostic Review Pipeline

Review pipeline yang bisa dipasang proyek lain: **code review**, **vulnerability
review**, dan **commit message review** — pilih yang dipakai, copot yang tidak.
Hasilnya satu report dengan severity **Critical / High / Medium / Low / Info**.

Multi-bahasa (mengikuti cakupan Semgrep & Trivy) dan gratis seluruhnya.

## Pakai

```yaml
# .github/workflows/review.yml
name: Review
on: [pull_request]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0        # commitlint memeriksa rentang commit PR

      - uses: supernurture/agnostic-pipeline-review@v1
        with:
          reviews: code,vulnerability     # <- pasang / copot di sini
          fail-on: high                   # default
```

Proyek A menulis `code,vulnerability`. Proyek B menulis `commit-message`. Tidak
ada file lain yang perlu diubah.

## Review yang tersedia

| Nama | Mesin | Cakupan |
|---|---|---|
| `code` | [Semgrep OSS](https://semgrep.dev) | Bug & pola rawan, 30+ bahasa |
| `vulnerability` | [Trivy](https://github.com/aquasecurity/trivy) + [Gitleaks](https://github.com/gitleaks/gitleaks) | CVE dependensi, misconfig IaC, secret bocor |
| `commit-message` | [commitlint](https://commitlint.js.org) | Conventional Commits |

## Input

| Input | Default | Keterangan |
|---|---|---|
| `reviews` | — | Wajib. Dipisah koma. Nama tak dikenal = gagal. |
| `fail-on` | `high` | `critical`, `high`, `medium`, `low`, `info`, atau `none` |
| `semgrep-config` | `p/ci` | Ruleset Semgrep, lihat [semgrep.dev/r](https://semgrep.dev/r) |
| `semgrep-version` | `1.173.0` | Versi engine. Rule-nya tetap segar — `p/ci` diambil dari registry saat run |
| `gitleaks-version` | `8.30.1` | Versi biner yang diunduh (checksum diverifikasi) |

Output `report-dir` berisi SARIF mentah tiap scanner, kalau kamu mau
mengunggahnya sebagai artifact.

## Severity

Tidak ada skala buatan sendiri. Formatnya **SARIF 2.1.0**, dan band-nya diambil
dari `properties.security-severity` — skor CVSS — memakai pembagian baku GitHub
code scanning:

| Band | Skor CVSS |
|---|---|
| Critical | ≥ 9.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| Info | tanpa skor / temuan non-security |

Scanner yang tidak memberi skor dipetakan lewat tabel fallback di
[`scripts/report.mjs`](scripts/report.mjs): temuan Gitleaks dianggap **Critical**
(kredensial hidup yang bocor bersifat kritis), Semgrep memakai level SARIF-nya.

## Report

Ditulis ke **Job Summary** GitHub, jadi langsung terbaca di halaman workflow run
— tanpa token tambahan dan tetap jalan di repo private.

```markdown
## Review Report

| Severity | Jumlah |
|---|---:|
| Critical | 2 |
| High | 5 |
| Medium | 11 |
| Low | 3 |
| Info | 8 |
| **Total** | **29** |

Gate: gagal pada **High** ke atas.

### Critical (2)
- `src/db.py:42` — gitleaks/aws-access-token
  AWS access token ditemukan
- `requirements.txt:3` — Trivy/CVE-2020-14343
  PyYAML 5.1: arbitrary code execution
```

Temuan commit message masuk section terpisah — gaya penulisan commit bukan
temuan keamanan, jadi ia tidak dipaksa masuk skala CVSS.

## Kapan build gagal

- Ada temuan pada atau di atas `fail-on`
- Ada pelanggaran commit message
- **Scanner yang diaktifkan tidak menghasilkan laporan**, atau SARIF-nya rusak

Poin terakhir sengaja tetap menggagalkan build bahkan saat `fail-on: none`:
scanner yang mati bukan berarti "tidak ada temuan", dan kegagalan seperti itu
tidak boleh lolos jadi hijau.

## Lane lokal (opsional)

[`presets/pre-commit.yaml`](presets/pre-commit.yaml) menjalankan scanner yang
sama di mesin developer sebagai gate cepat pass/fail. Salin ke
`.pre-commit-config.yaml`, lalu:

```sh
pre-commit install --install-hooks -t pre-commit -t commit-msg
```

Ia tidak menghasilkan report bertingkat severity — pre-commit hanya
mengembalikan exit code. Sumber kebenarannya tetap CI.

## Menambah jenis review baru

Dua tempat, dan memang cuma dua:

1. Tambah step di [`action.yml`](action.yml) yang menulis SARIF ke `$REPORT_DIR`,
   plus nama filenya di `expect` pada step validasi.
2. Kalau tool-nya tidak mengisi `security-severity`, tambah satu entri di
   `TOOL_FALLBACK` di [`scripts/report.mjs`](scripts/report.mjs).

Tool yang sudah emit SARIF ber-`security-severity` tidak butuh perubahan
`report.mjs` sama sekali.

## Pengembangan

```sh
node scripts/report.test.mjs
```

Butuh Node ≥ 18.3 (`util.parseArgs`). Runner GitHub sudah memenuhinya tanpa
step setup apa pun.

`.github/workflows/self-test.yml` menjalankan self-check itu lalu memakai
`examples/fixtures/` untuk membuktikan tiap scanner memang menemukan sesuatu —
dan bahwa temuannya hilang saat review-nya dicopot.

## Lisensi

[MIT](LICENSE). Scanner yang dipanggilnya punya lisensinya sendiri: Semgrep OSS
(LGPL-2.1), Trivy (Apache-2.0), Gitleaks (MIT), commitlint (MIT) — semuanya
dijalankan sebagai proses terpisah, bukan ditautkan ke dalam kode ini.
