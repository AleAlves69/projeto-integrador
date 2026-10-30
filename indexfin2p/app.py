import os

from cryptography.fernet import Fernet
from authlib.integrations.flask_client import OAuth
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix

from indexfin2 import database
from indexfin2.admin_routes import register_routes as register_admin_routes
from indexfin2.auth_routes import register_routes as register_auth_routes
from indexfin2.dashboard_routes import register_routes as register_dashboard_routes
from indexfin2.database import BASE_DIR, DB_PATH, SCHEMA_PATH, close_db, get_db, seed_data as _seed_data
from indexfin2.fiscal_routes import register_routes as register_fiscal_routes
from indexfin2.request_routes import register_routes as register_request_routes
from indexfin2.security import (
    AVAILABLE_ROLES, MFA_ROLES, ROLE_ALIASES, ROLE_GROUPS, SELF_REGISTRATION_ROLES,
    begin_login, establish_login, get_current_user, get_preauth_user, login_required,
    normalize_role, requires_totp, role_allowed, role_required, safe_next_url,
)
from indexfin2.services import (
    can_access_request, get_approval_requirement, get_budget_for_request,
    get_quote_comparison, get_quotes_for_request, get_request_by_id,
    get_request_items, is_last_active_admin, log_audit, log_user_audit,
    render_user_management, set_request_status, valid_company_id,
)

app = Flask(__name__)
production = os.environ.get("APP_ENV", "").lower() == "production"
secret_key = os.environ.get("SECRET_KEY")
if production and not secret_key:
    raise RuntimeError("Configure SECRET_KEY before running IndexFin2 in production.")
if production and not os.environ.get("DATABASE_PATH"):
    raise RuntimeError("Configure DATABASE_PATH to a persistent production database location.")
cpf_encryption_key = os.environ.get("CPF_ENCRYPTION_KEY")
if production and not cpf_encryption_key:
    raise RuntimeError("Configure CPF_ENCRYPTION_KEY as a persistent Fernet key in production.")
if cpf_encryption_key:
    try:
        Fernet(cpf_encryption_key.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as error:
        raise RuntimeError("CPF_ENCRYPTION_KEY must be a valid persistent Fernet key.") from error

cookie_secure = os.environ.get("COOKIE_SECURE", "").lower() in {"1", "true", "yes"}
if production and not cookie_secure:
    raise RuntimeError("Set COOKIE_SECURE=true when running IndexFin2 in production.")

app.config["SECRET_KEY"] = secret_key or os.urandom(32)
app.config["CPF_ENCRYPTION_KEY"] = cpf_encryption_key
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = cookie_secure
if production:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

oauth = OAuth(app)
SSO_PROVIDERS = {}

google_client_id = os.environ.get("GOOGLE_CLIENT_ID")
google_client_secret = os.environ.get("GOOGLE_CLIENT_SECRET")
if google_client_id and google_client_secret:
    oauth.register(
        name="google",
        client_id=google_client_id,
        client_secret=google_client_secret,
        server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
        client_kwargs={"scope": "openid email profile"},
    )
    SSO_PROVIDERS["google"] = "Google"

microsoft_client_id = os.environ.get("MICROSOFT_CLIENT_ID")
microsoft_client_secret = os.environ.get("MICROSOFT_CLIENT_SECRET")
microsoft_tenant_id = os.environ.get("MICROSOFT_TENANT_ID", "common")
if microsoft_client_id and microsoft_client_secret:
    oauth.register(
        name="microsoft",
        client_id=microsoft_client_id,
        client_secret=microsoft_client_secret,
        server_metadata_url=(
            f"https://login.microsoftonline.com/{microsoft_tenant_id}/v2.0/"
            ".well-known/openid-configuration"
        ),
        client_kwargs={"scope": "openid email profile"},
    )
    SSO_PROVIDERS["microsoft"] = "Microsoft"

app.config["DB_PATH_PROVIDER"] = lambda: DB_PATH
app.config["SSO_PROVIDERS"] = SSO_PROVIDERS
app.config["OAUTH"] = oauth
app.teardown_appcontext(close_db)
register_auth_routes(app)
register_admin_routes(app)
register_dashboard_routes(app)
register_request_routes(app)
register_fiscal_routes(app)

def init_db():
    return database.init_db(
        DB_PATH,
        SCHEMA_PATH,
        production=production,
        bootstrap_admin_email=os.environ.get("BOOTSTRAP_ADMIN_EMAIL"),
        bootstrap_admin_password=os.environ.get("BOOTSTRAP_ADMIN_PASSWORD"),
    )

def seed_data():
    return _seed_data(DB_PATH)


if __name__ == "__main__":
    init_db()
    app.run(
        debug=os.environ.get("APP_DEBUG", "").lower() in {"1", "true", "yes"},
        host="127.0.0.1",
        port=5000,
    )
