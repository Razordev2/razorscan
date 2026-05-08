# Razorscan - Professional Bug Bounty Analysis Tool

Razorscan adalah toolkit CLI untuk membantu proses reconnaissance, security auditing, dan hunting vulnerability secara cepat pada target web/API.

## Source Credit

Project source diadaptasi/dikreditkan ke:
- Razordev2: [https://github.com/Razordev2](https://github.com/Razordev2)

## Fitur Utama

- Full target scan dengan multi-phase security checks.
- Security header analysis.
- Sensitive exposure scanner (backup, config, credentials files).
- JavaScript endpoint extraction + secret scanning.
- Opportunity scanner (keyword sensitif, parameter berisiko, indikasi IP internal).
- Cloud bucket discovery (termasuk S3 checks).
- Robots.txt hidden paths discovery.
- Parameter mining untuk potensi celah high impact.
- Source map hunting.
- CMS hunters:
  - WordPress audit.
  - Moodle audit.
  - Liferay endpoint hunting + bypass check.
- Passive intel:
  - Subdomain discovery.
  - Wayback historical URL intel.
- API documentation exposure audit.
- Manual HTTP request/repeater mode.
- JSON diff helper untuk indikasi auth/IDOR issue.
- JSON report output + optional HTML report.

## Preview

![Razorscan Preview](img/Screenshot%202026-05-08%20145413.png)

## Instalasi

```bash
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
# .venv\Scripts\activate   # Windows PowerShell
pip install -r requirements.txt
```

## Menjalankan

```bash
python main.py
```

Atau gunakan command langsung dari Typer CLI:

```bash
python main.py scan example.com --deep
python main.py intel example.com
python main.py api-audit example.com
python main.py request https://example.com --method GET
python main.py diff reports/a.json reports/b.json
```

## Struktur Direktori Singkat

- `main.py` - entrypoint aplikasi.
- `razorscan/cli.py` - command definitions dan orchestrator scan.
- `razorscan/modules/` - modul hunter/scanner.
- `reports/` - output JSON scan.
- `templates/` - template HTML report.
- `img/` - aset gambar.

## Disclaimer

Gunakan tools ini hanya untuk target yang Anda miliki izin resmi untuk diuji. Segala penyalahgunaan menjadi tanggung jawab pengguna.
