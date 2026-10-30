import os

if os.environ.get("APP_ENV", "").lower() != "production":
    raise RuntimeError("Set APP_ENV=production before starting the production server.")

from waitress import serve

from app import app, init_db

init_db()
os.environ.pop("BOOTSTRAP_ADMIN_PASSWORD", None)
os.environ.pop("BOOTSTRAP_ADMIN_EMAIL", None)
serve(app, host="127.0.0.1", port=8080, threads=8)
