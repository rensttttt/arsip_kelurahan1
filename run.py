import os
from arsip_flask import create_app

# Ambil environment config
env = os.environ.get("FLASK_ENV", "production").lower()

# Buat aplikasi berdasarkan konfigurasi (misalnya: development, testing, production)
app = create_app()

# Untuk development, aktifkan run bawaan Flask
if __name__ == "__main__":
    debug_mode = env == "development"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_mode)
