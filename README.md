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


## Stage
|     Environment     |      Tujuan        |   Keterangan                       |
|---------------------|--------------------|------------------------------------|
| development         | Coding harian      | Debug aktif, DB lokal              |
| preview / staging   | Final review UI/UX | Gunakan data dummy production-like |
| testing             | Unit test / CI     | Isolasi otomatis                   |
| production          | Live user          | Aman, cepat, tanpa debug           |

## Package & Dependency Manager
> Keterangan mengapa kita menggunakan poetry (stage: development) sedangkan pip (stage: release)

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


## Production (disarankan menggunakan pip)
### untuk production wajib inisiasi .env
```yml
# .env
FLASK_ENV=production
FLASK_APP=flask
FLASK_DEBUG=0
```
### contoh test manual
```bash
#!/bin/sh
poetry add gunicorn
poetry run gunicorn -w 4 -b 0.0.0.0:5000 'arsip_flask:create_app()'
```
### cek venv apakah sudah benar
```bash
dev@isp:~/arsip_kelurahan1$ poetry shell
Creating virtualenv arsip-flask in /home/dev/arsip_kelurahan1/.venv
Spawning shell within /home/dev/arsip_kelurahan1/.venv
. /home/dev/arsip_kelurahan1/.venv/bin/activate
dev@isp:~/arsip_kelurahan1$ . /home/dev/arsip_kelurahan1/.venv/bin/activate
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ which python
/home/dev/arsip_kelurahan1/.venv/bin/python
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ poetry env info

Virtualenv
Python:         3.12.3
Implementation: CPython
Path:           /home/dev/arsip_kelurahan1/.venv
Executable:     /home/dev/arsip_kelurahan1/.venv/bin/python
Valid:          True

Base
Platform:   linux
OS:         posix
Python:     3.12.3
Path:       /home/dev/.pyenv/versions/3.12.3
Executable: /home/dev/.pyenv/versions/3.12.3/bin/python3.12
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ poetry env info --path
/home/dev/arsip_kelurahan1/.venv
```

### install dependensi
```bash
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ poetry install
Installing dependencies from lock file

Package operations: 70 installs, 0 updates, 0 removals
  - Installing slixmpp (1.10.0)
  - Installing redis (5.3.0)
  - Installing structlog (24.4.0)

Installing the current project: arsip-flask (0.1.0)
```
### membuat dan menjalankan supervisor
```bash
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ vim /etc/supervisor/conf.d/arsip_app.conf
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ sudo supervisorctl reread
arsip_app: disappeared
arsip_kelurahan1: available
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ sudo supervisorctl update
arsip_app: stopped
sudo supervisorctl restart arsip_app
```

### menggunakan [Akses Tunnel](https://github.com/konxc/akses) untuk membuat Zero Trust [Cloudflare Tunnel](https://github.com/cloudflare/cloudflared)
#### [Akses Tunnel](https://github.com/konxc/akses)
```bash
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ auto-tunnel-config.sh 
🚀 Cloudflare Tunnel Auto Configuration
======================================

📋 Pilih tunnel yang akan dikonfigurasi:
  1) bun-tracker (ID: 8d409de4...)
  2) core (ID: d6895009...)
  3) devel_home (ID: ddfa7b46...)
  4) project-arsip (ID: c8e8dc0b...)
  5) 🆕 Buat tunnel baru

Pilih nomor (1-5): 4
⚠️  Konfigurasi tunnel 'project-arsip' sudah ada!

Detail konfigurasi:
  Tunnel ID: c8e8dc0b-178e-4719-8ab4-ff3cdf08b4b2
  Hostname: hostname:
  Service: 
  Config file: /home/dev/.cloudflared/config.yml

Untuk melihat config lengkap: cat /home/dev/.cloudflared/config.yml
Untuk menjalankan tunnel: cloudflared tunnel run project-arsip
Untuk mengupdate config: hapus file /home/dev/.cloudflared/config.yml dan jalankan script ini lagi
```
#### [Cloudflare Tunnel](https://github.com/cloudflare/cloudflared)
```bash
(arsip-flask-py3.12) dev@isp:~/arsip_kelurahan1$ cloudflared tunnel run project-arsip
2025-06-15T06:41:24Z INF Starting tunnel tunnelID=c8e8dc0b-178e-4719-8ab4-ff3cdf08b4b2
2025-06-15T06:41:24Z INF Version 2025.6.0 (Checksum 173276e3370f366493fb818ebe33cca23a9601d721ca3c03085b3f838eaf3ca9)
2025-06-15T06:41:24Z INF GOOS: linux, GOVersion: go1.24.2, GoArch: amd64
2025-06-15T06:41:24Z INF Settings: map[cred-file:/home/dev/.cloudflared/c8e8dc0b-178e-4719-8ab4-ff3cdf08b4b2.json credentials-file:/home/dev/.cloudflared/c8e8dc0b-178e-4719-8ab4-ff3cdf08b4b2.json loglevel:info proto-loglevel:info transport-loglevel:info]
2025-06-15T06:41:24Z INF cloudflared will not automatically update if installed by a package manager.
2025-06-15T06:41:24Z INF Generated Connector ID: ac56ed0d-32dd-4b53-8932-ef799721a121
2025-06-15T06:41:24Z INF Initial protocol quic
2025-06-15T06:41:24Z INF ICMP proxy will use 192.168.88.12 as source for IPv4
2025-06-15T06:41:24Z INF ICMP proxy will use fe80::a00:27ff:fee2:7d75 in zone enp0s3 as source for IPv6
2025-06-15T06:41:24Z WRN The user running cloudflared process has a GID (group ID) that is not within ping_group_range. You might need to add that user to a group within that range, or instead update the range to encompass a group the user is already in by modifying /proc/sys/net/ipv4/ping_group_range. Otherwise cloudflared will not be able to ping this network error="Group ID 1000 is not between ping group 1 to 0"
2025-06-15T06:41:24Z WRN ICMP proxy feature is disabled error="cannot create ICMPv4 proxy: Group ID 1000 is not between ping group 1 to 0 nor ICMPv6 proxy: socket: permission denied"
2025-06-15T06:41:24Z INF ICMP proxy will use 192.168.88.12 as source for IPv4
2025-06-15T06:41:24Z INF ICMP proxy will use fe80::a00:27ff:fee2:7d75 in zone enp0s3 as source for IPv6
2025-06-15T06:41:24Z INF Starting metrics server on 127.0.0.1:20241/metrics
2025-06-15T06:41:24Z INF Tunnel connection curve preferences: [X25519MLKEM768 CurveID(25497) CurveP256] connIndex=0 event=0 ip=198.41.200.13
2025/06/15 13:41:24 failed to sufficiently increase receive buffer size (was: 208 kiB, wanted: 7168 kiB, got: 416 kiB). See https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes for details.
2025-06-15T06:41:25Z INF Registered tunnel connection connIndex=0 connection=ebd25406-abac-4485-a9d2-6c2cc5b8bd78 event=0 ip=198.41.200.13 location=sin13 protocol=quic2025-06-15T06:41:25Z INF Tunnel connection curve preferences: [X25519MLKEM768 CurveID(25497) CurveP256] connIndex=1 event=0 ip=198.41.192.67
2025-06-15T06:41:26Z INF Registered tunnel connection connIndex=1 connection=c038d5ec-0dc5-4637-b3ad-c1a6aea7f736 event=0 ip=198.41.192.67 location=sin17 protocol=quic2025-06-15T06:41:26Z INF Tunnel connection curve preferences: [X25519MLKEM768 CurveID(25497) CurveP256] connIndex=2 event=0 ip=198.41.200.73
2025-06-15T06:41:27Z INF Registered tunnel connection connIndex=2 connection=cc42a588-b518-45ad-8df8-511004da7b2c event=0 ip=198.41.200.73 location=sin02 protocol=quic2025-06-15T06:41:27Z INF Tunnel connection curve preferences: [X25519MLKEM768 CurveID(25497) CurveP256] connIndex=3 event=0 ip=198.41.192.77
2025-06-15T06:41:28Z INF Registered tunnel connection connIndex=3 connection=23d9276c-4f60-4eba-abbe-467482cf1166 event=0 ip=198.41.192.77 location=sin17 protocol=quic
```
---

## Reproduce atau development (disarankan menggunakan poetry daripada pip)
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

