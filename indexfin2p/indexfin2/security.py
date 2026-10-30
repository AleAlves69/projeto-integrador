from functools import wraps
from urllib.parse import urljoin, urlparse

from flask import redirect, render_template, request, session, url_for

from .database import get_db

ROLE_GROUPS = {
    "admin": {"admin"},
    "operador": {"operador", "operador_comercial", "operador_financeiro"},
    "cliente": {"cliente"},
    "fornecedor": {"fornecedor"},
    "auditor": {"auditor"},
}
ROLE_ALIASES = {role: group for group, roles in ROLE_GROUPS.items() for role in roles}
ROLE_ALIASES["operador"] = "operador"
AVAILABLE_ROLES = (
    "admin",
    "operador",
    "operador_comercial",
    "operador_financeiro",
    "cliente",
    "fornecedor",
    "auditor",
)
SELF_REGISTRATION_ROLES = ("cliente", "operador_comercial", "operador_financeiro")

MFA_ROLES = {"operador", "operador_comercial", "operador_financeiro", "auditor"}


def requires_totp(role):
    return normalize_role(role) in MFA_ROLES

def safe_next_url(target):
    if not target:
        return url_for("dashboard")
    base = urlparse(request.host_url)
    candidate = urlparse(urljoin(request.host_url, target))
    if candidate.scheme in {"http", "https"} and candidate.netloc == base.netloc:
        return target
    return url_for("dashboard")

def establish_login(user, next_url=None):
    session.clear()
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["full_name"] = user["full_name"]
    session["totp_verified"] = True
    if not user["cpf_ciphertext"]:
        return redirect(url_for("completar_cadastro_cpf", next=safe_next_url(next_url)))
    return redirect(safe_next_url(next_url))

def begin_login(user, next_url=None):
    if requires_totp(user["role"]):
        session.clear()
        session["preauth_user_id"] = user["id"]
        session["preauth_next"] = safe_next_url(next_url)
        if user["totp_enabled"]:
            return redirect(url_for("verificar_totp"))
        return redirect(url_for("configurar_totp"))
    return establish_login(user, next_url)

def get_preauth_user():
    user_id = session.get("preauth_user_id")
    if not user_id:
        return None
    user = get_db().execute("SELECT * FROM users WHERE id = ? AND active = 1", (user_id,)).fetchone()
    if user is None:
        session.clear()
    return user

def normalize_role(role_name):
    if role_name is None:
        return None
    normalized = str(role_name).strip().lower()
    return ROLE_ALIASES.get(normalized, normalized)

def role_allowed(user_role, allowed_roles):
    if user_role is None:
        return False
    user_group = normalize_role(user_role)
    required_groups = {normalize_role(role_name) for role_name in allowed_roles}
    return user_group in required_groups

def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login", next=request.path))
        user = get_current_user()
        if user is None or not user["active"]:
            session.clear()
            return redirect(url_for("login", error="Sua conta está inativa. Fale com o administrador."))
        if not user["cpf_ciphertext"] and request.endpoint != "completar_cadastro_cpf":
            return redirect(url_for("completar_cadastro_cpf", next=request.path))
        if requires_totp(user["role"]) and (
            not user["totp_enabled"] or not session.get("totp_verified")
        ):
            session.clear()
            session["preauth_user_id"] = user["id"]
            session["preauth_next"] = request.path
            return redirect(
                url_for("configurar_totp") if not user["totp_enabled"] else url_for("verificar_totp")
            )
        session["username"] = user["username"]
        session["role"] = user["role"]
        session["full_name"] = user["full_name"]
        return view(*args, **kwargs)

    return wrapped

def role_required(*allowed_roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user is None or not role_allowed(user["role"], allowed_roles):
                return render_template("forbidden.html", user=user), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator
