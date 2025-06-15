# gunicorn.conf.py
import os

# Replace with your application's entry point
wsgi_app = "wsgi:app"

workers = os.cpu_count() * 2 + 1
bind = "localhost:5000"
accesslog = "logs/gunicorn.access.log"
errorlog = "logs/gunicorn.error.log"
loglevel = "info"
timeout = 120

