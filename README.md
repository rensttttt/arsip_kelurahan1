# 🗂️ Arsip Desa Digital
> Aplikasi pengelolaan arsip digital tingkat desa/kelurahan berbasis web dengan Python Flask.


## 🚀 Fitur Utama

* Manajemen akun: register, login, ganti password, profil pengguna
* Upload dan listing arsip
* Filter berdasarkan kategori, tanggal, dan pencarian judul
* Dashboard statistik pengarsipan
* Role pengguna: admin dan warga (rencana)
* Logging sistem dan aktivitas pengguna

---

## 🛠️ Struktur Folder

```
arsip_app/
├── arsip_flask/               # Source utama aplikasi
│   ├── __init__.py            # Application factory
│   ├── config.py              # Konfigurasi Dev/Prod
│   ├── routes/                # Blueprint routes
│   │   ├── auth.py
│   │   ├── user.py
│   │   ├── dashboard.py
│   │   ├── archive.py
│   │   └── activity.py
│   ├── forms/                 # Formulir WTForms
│   ├── models/                # Model User dll.
│   ├── utils/                 # Helper: logging, sanitizer, pagination
│   ├── templates/             # Template Jinja2 modular
│   │   ├── base.html
│   │   ├── auth/
│   │   ├── user/
│   │   ├── archive/
│   │   ├── dashboard/
│   │   └── errors/
│   └── static/                # (Opsional) file statis
├── logs/                      # File log
├── .env                       # Konfigurasi lingkungan
├── .env.example               # Contoh file env
├── pyproject.toml             # Konfigurasi Poetry
├── poetry.lock                # Lockfile Poetry
├── requirements.txt           # Untuk pip production
├── run.py                     # Entrypoint dev
├── README.md                  # Dokumentasi proyek
├── LICENSE                    # Lisensi
├── .venv/                     # Python Virtual Env (activate using poetry shell)
└── environment (opsional)
```

---

## 📦 Cara Instalasi (Development)

### 🔁 Clone & Masuk Folder

```bash
git clone https://github.com/namauser/aplikasi-desa-digital.git
cd aplikasi-desa-digital
```

### 🧪 Gunakan [Poetry](https://python-poetry.org/docs/#installation)

```bash
poetry install

# jika ingin menggunakan `poetry shell`
poetry self add poetry-plugin-shell

# jika membutuhkan poetry export (freezing requirement.txt)
poetry self add poetry-plugin-export

# activate python virtual environment on your shell
poetry shell
```

### 🔐 Salin `.env` dan konfigurasi awal

```bash
cp .env.example .env
```

### 🛠️ Jalankan Aplikasi (Dev)

```bash
flask run --debug
```

> Catatan: gunakan Python 3.12 atau versi yang sesuai dari `pyproject.toml`

---

## 📦 Instalasi dengan `pip` (Preview/Production)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
FLASK_ENV=production flask run
```

> Untuk produksi: gunakan `gunicorn`, reverse proxy (NGINX), dan sistem supervisi (misal: systemd)

---

## 🐳 Docker (Opsional)

> Masih dalam tahap pengembangan

```bash
docker-compose up --build
```

---

## 🔧 Rencana & Roadmap

Lihat roadmap lengkap di dokumen `Tab Project Repository`, namun ringkasnya:


### 📌 Tahap Saat Ini
* [x] Struktur modular dengan Blueprint
* [x] Login, register, dan profil pengguna
* [x] Upload dan listing arsip dasar
* [x] Filter, pencarian, dan pagination arsip
* [x] Template rapi dan konsisten
* [x] Logging aktivitas pengguna


### 📈 Fitur dan Milestone Berikutnya

#### 🔄 Refaktor & Perluasan
* [ ] Unit test & coverage untuk sanitasi dan login
* [ ] Error page custom (403, 404, 500)
* [ ] Dokumentasi API internal (jika ada JSON route)

#### 🐳 DevOps
* [ ] Dockerfile & docker-compose.yaml
* [ ] GitHub Actions untuk CI/CD
* [ ] Deployment ke VPS dengan reverse proxy

#### 🔐 Keamanan & Validasi
* [ ] Pembatasan file upload & validasi MIME
* [ ] Verifikasi admin atas arsip yang masuk
* [ ] Logging audit sistem

#### 📤 Fitur Lanjutan
* [ ] Export PDF dari data arsip
* [ ] Upload multi-file & preview
* [ ] Komentar atau status verifikasi arsip
* [ ] Role admin desa vs kecamatan
* [ ] Notifikasi via email / WhatsApp
* [ ] UI mobile-first atau PWA

---


# Stage
|     Environment     |      Tujuan        |   Keterangan                       |
|---------------------|--------------------|------------------------------------|
| development         | Coding harian      | Debug aktif, DB lokal              |
| preview / staging   | Final review UI/UX | Gunakan data dummy production-like |
| testing             | Unit test / CI     | Isolasi otomatis                   |
| production          | Live user          | Aman, cepat, tanpa debug           |

# Package & Dependency Manager
| Fitur / Alat                       | `pip`                  | `poetry`                         | `npm` (Node.js)                                 |
| ---------------------------------- | ---------------------- | -------------------------------- | ----------------------------------------------- |
| Bahasa Target                      | Python                 | Python                           | JavaScript / Node.js                            |
| Jenis Alat                         | Package Installer      | Dependency & Project Manager     | Package & Dependency Manager                    |
| Instal Paket                       | ✅ Ya                   | ✅ Ya                             | ✅ Ya                                            |
| Kelola Versi Proyek                | ❌ Tidak                | ✅ Ya                             | ✅ Ya (via `engines` field)                      |
| Buat Virtual Environment           | ❌ Tidak otomatis       | ✅ Otomatis                       | ❌ Tidak diperlukan (isolasi via `node_modules`) |
| File Konfigurasi Utama             | `requirements.txt`     | `pyproject.toml` + `poetry.lock` | `package.json` + `package-lock.json`            |
| Dependency Resolver (Smart)        | ⚠️ Dasar               | ✅ Canggih & Konsisten            | ✅ Canggih (sejak npm v7+)                       |
| Buat & Publikasi Paket ke Registry | ⚠️ Manual (`setup.py`) | ✅ Built-in (`poetry publish`)    | ✅ Built-in (`npm publish`)                      |
| Kompatibel untuk CI/CD             | ✅ Ya                   | ✅ Ya                             | ✅ Ya                                            |
| Cocok untuk Proyek Skala Besar     | ⚠️ Perlu tambahan alat | ✅ Sangat cocok                   | ✅ Ya                                            |


# Production (disarankan menggunakan pip)
```yml
# Flask Configuration
FLASK_ENV=production
FLASK_APP=flask
FLASK_DEBUG=0
```
```bash
poetry add gunicorn
poetry run gunicorn -w 4 -b 0.0.0.0:5000 'arsip_flask:create_app()'
```

# Reproduce (disarankan menggunakan poetry daripada pip)
```bash
dev@isp:~/arsip_app$ poetry shell
Creating virtualenv arsip-flask in /home/dev/arsip_app/.venv
Spawning shell within /home/dev/arsip_app/.venv
. /home/dev/arsip_app/.venv/bin/activate
dev@isp:~/arsip_app$ . /home/dev/arsip_app/.venv/bin/activate
(arsip-flask-py3.12) dev@isp:~/arsip_app$ poetry install
Installing dependencies from lock file

Package operations: 70 installs, 0 updates, 0 removals

  - Installing markupsafe (3.0.2)
  - Installing pycparser (2.22)
  - Installing blinker (1.9.0)
  - Installing cffi (1.17.1)
  - Installing click (8.2.1)
  - Installing greenlet (3.2.3)
  - Installing itsdangerous (2.2.0)
  - Installing jinja2 (3.1.6)
  - Installing mdurl (0.1.2)
  - Installing typing-extensions (4.14.0)
  - Installing werkzeug (3.1.3)
  - Installing wrapt (1.17.2)
  - Installing deprecated (1.2.18)
  - Installing flask (2.3.3)
  - Installing mako (1.3.10)
  - Installing markdown-it-py (3.0.0)
  - Installing packaging (25.0)
  - Installing pyasn1 (0.6.1)
  - Installing pycares (4.9.0)
  - Installing pygments (2.19.1)
  - Installing sqlalchemy (2.0.41)
  - Installing aiodns (3.5.0)
  - Installing alembic (1.16.1)
  - Installing babel (2.17.0)
  - Installing dnspython (2.7.0)
  - Installing flask-sqlalchemy (3.1.1)
  - Installing idna (3.10)
  - Installing iniconfig (2.1.0)
  - Installing limits (5.3.0)
  - Installing mccabe (0.7.0)
  - Installing mypy-extensions (1.1.0)
  - Installing ordered-set (4.1.0)
  - Installing pathspec (0.12.1)
  - Installing platformdirs (4.3.8)
  - Installing pluggy (1.6.0)
  - Installing protobuf (3.20.3)
  - Installing psycopg-binary (3.2.9)
  - Installing pyasn1-modules (0.4.2)
  - Installing pycodestyle (2.11.1)
  - Installing pyflakes (3.1.0)
  - Installing pyjwt (2.9.0)
  - Installing pytz (2025.2)
  - Installing rich (13.9.4)
  - Installing six (1.17.0)
  - Installing webencodings (0.5.1)
  - Installing wtforms (3.2.1)
  - Installing black (23.12.1)
  - Installing bleach (6.2.0)
  - Installing email-validator (2.2.0)
  - Installing flake8 (6.1.0)
  - Installing flask-babel (4.0.0)
  - Installing flask-limiter (3.12)
  - Installing flask-login (0.6.3)
  - Installing flask-mail (0.10.0)
  - Installing flask-mailman (1.1.1)
  - Installing flask-migrate (4.1.0)
  - Installing flask-talisman (1.1.0)
  - Installing flask-wtf (1.2.2)
  - Installing gunicorn (23.0.0)
  - Installing mypy (1.16.0)
  - Installing mysql-connector-python (8.0.32)
  - Installing pillow (10.4.0)
  - Installing psycopg (3.2.9)
  - Installing pytest (7.4.4)
  - Installing python-dateutil (2.9.0.post0)
  - Installing python-dotenv (1.1.0)
  - Installing python-magic (0.4.27)
  - Installing redis (5.3.0)
  - Installing slixmpp (1.10.0)
  - Installing structlog (24.4.0)

Installing the current project: arsip-flask (0.1.0)
(arsip-flask-py3.12) dev@isp:~/arsip_app$ exit
exit
dev@isp:~/arsip_app$ poetry env info

Virtualenv
Python:         3.12.3
Implementation: CPython
Path:           /home/dev/arsip_app/.venv
Executable:     /home/dev/arsip_app/.venv/bin/python
Valid:          True

Base
Platform:   linux
OS:         posix
Python:     3.12.3
Path:       /home/dev/.pyenv/versions/3.12.3
Executable: /home/dev/.pyenv/versions/3.12.3/bin/python3.12
dev@isp:~/arsip_app$ poetry shell
Spawning shell within /home/dev/arsip_app/.venv
. /home/dev/arsip_app/.venv/bin/activate
dev@isp:~/arsip_app$ . /home/dev/arsip_app/.venv/bin/activate
(arsip-flask-py3.12) dev@isp:~/arsip_app$ python run.py 
[2025-06-15 05:47:00,830] INFO in logging: Logging is set up.
INFO: Logging is set up.
 * Serving Flask app 'arsip_flask'
 * Debug mode: on
WARNING: This is a development server. Do not use it in a production deployment. Use a production WSGI server instead.
 * Running on all addresses (0.0.0.0)
 * Running on http://127.0.0.1:5000
 * Running on http://192.168.88.12:5000
Press CTRL+C to quit
 * Restarting with stat
[2025-06-15 05:47:01,334] INFO in logging: Logging is set up.
INFO: Logging is set up.
 * Debugger is active!
```
---

## Cara Menggunakan Logger
1. **opsi-1:** gunakan `current_app` jika logger digunakan diluar `def create_app()`
    ```python3
    from flask import current_app
    current_app.logger.info("Ini info biasa")
    ```
2. **opsi-2:** gunakan app jika logger digunakan didalam `def create_app()`
    ```
    def create_app():
        app = Flask(__name__)
        app.logger.warning("contoh peringatan")
    ```

## 🤝 Kontribusi

Pull request terbuka untuk perbaikan bug, pengembangan fitur, dan pengamanan. Silakan fork dan gunakan branch terpisah.

