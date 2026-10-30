import re
import sqlite3

import pyotp
from flask import current_app, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .database import get_db
from .identity import (
    IdentityConfigurationError, format_cnpj, normalize_cnpj, normalize_cpf,
    protect_cpf,
)
from .security import (
    AVAILABLE_ROLES, SELF_REGISTRATION_ROLES, begin_login, establish_login,
    get_current_user, get_preauth_user, login_required, normalize_role,
    requires_totp, role_allowed, role_required, safe_next_url,
)
from .services import (
    can_access_request, get_approval_requirement, get_budget_for_request,
    get_quote_comparison, get_quotes_for_request, get_request_by_id,
    get_request_items, is_last_active_admin, log_audit, log_user_audit,
    render_user_management, set_request_status, valid_company_id,
)

def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user and user["active"] and check_password_hash(user["password_hash"], password):
            return begin_login(user, request.args.get("next"))

        error = "Sua conta está inativa. Fale com o administrador." if user and not user["active"] else "Credenciais inválidas."
        return render_template(
            "login.html",
            error=error,
            sso_providers=current_app.config["SSO_PROVIDERS"],
        )

    return render_template(
        "login.html",
        error=request.args.get("error"),
        sso_providers=current_app.config["SSO_PROVIDERS"],
    )


def completar_cadastro_cpf():
    user_id = session.get("user_id")
    if not user_id:
        return redirect(url_for("login"))
    db = get_db()
    user = db.execute(
        "SELECT id, username, company_id, cpf_ciphertext FROM users WHERE id = ? AND active = 1",
        (user_id,),
    ).fetchone()
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    if user["cpf_ciphertext"]:
        return redirect(safe_next_url(request.args.get("next")))

    if request.method == "POST":
        cpf = normalize_cpf(request.form.get("cpf", ""))
        if cpf is None:
            return render_template(
                "completar_cadastro_cpf.html",
                error="CPF inválido. Verifique os dígitos.",
            ), 400
        try:
            encrypted, lookup = protect_cpf(cpf)
        except IdentityConfigurationError as error:
            return render_template(
                "completar_cadastro_cpf.html", error=str(error)
            ), 503
        if db.execute("SELECT 1 FROM users WHERE cpf_lookup = ?", (lookup,)).fetchone():
            return render_template(
                "completar_cadastro_cpf.html",
                error="CPF já cadastrado. Fale com o administrador.",
            ), 409
        try:
            db.execute(
                "UPDATE users SET cpf_ciphertext = ?, cpf_lookup = ? WHERE id = ? AND cpf_ciphertext IS NULL",
                (encrypted, lookup, user_id),
            )
            db.commit()
        except sqlite3.IntegrityError:
            db.rollback()
            return render_template(
                "completar_cadastro_cpf.html",
                error="CPF já cadastrado. Fale com o administrador.",
            ), 409
        log_user_audit(
            "cpf_cadastrado",
            "CPF informado pelo próprio usuário e armazenado criptografado.",
            user_id,
            user["company_id"],
        )
        return redirect(safe_next_url(request.args.get("next")))

    return render_template("completar_cadastro_cpf.html", error=None)


def sso_login(provider):
    if provider not in current_app.config["SSO_PROVIDERS"]:
        return redirect(url_for("login", error="Este provedor SSO não está configurado."))
    client = current_app.config["OAUTH"].create_client(provider)
    session["sso_next"] = safe_next_url(request.args.get("next"))
    callback = url_for("sso_callback", provider=provider, _external=True)
    return client.authorize_redirect(callback)


def sso_callback(provider):
    if provider not in current_app.config["SSO_PROVIDERS"]:
        return redirect(url_for("login", error="Este provedor SSO não está configurado."))
    client = current_app.config["OAUTH"].create_client(provider)
    token = client.authorize_access_token()
    claims = token.get("userinfo") or client.parse_id_token(token)
    email = (claims.get("email") or claims.get("preferred_username") or "").strip().lower()
    subject = claims.get("sub")
    if not email or not subject or claims.get("email_verified") is False:
        return redirect(url_for("login", error="O provedor não confirmou uma identidade de e-mail válida."))

    db = get_db()
    subject_column = "google_sub" if provider == "google" else "microsoft_sub"
    user = db.execute(
        f"SELECT * FROM users WHERE {subject_column} = ?",
        (subject,),
    ).fetchone()
    if user is None:
        matches = db.execute(
            "SELECT * FROM users WHERE lower(email) = ?",
            (email,),
        ).fetchall()
        if len(matches) != 1:
            return redirect(url_for("login", error="Conta não autorizada ou e-mail associado a mais de uma conta. Fale com o administrador."))
        user = matches[0]
        if not user["active"]:
            return redirect(url_for("login", error="Sua conta está inativa. Fale com o administrador."))
        try:
            db.execute(
                f"UPDATE users SET {subject_column} = ? WHERE id = ? AND {subject_column} IS NULL",
                (subject, user["id"]),
            )
            db.commit()
        except sqlite3.IntegrityError:
            return redirect(url_for("login", error="Esta identidade SSO já está vinculada a outra conta."))
        user = db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()

    if not user["active"]:
        return redirect(url_for("login", error="Sua conta está inativa. Fale com o administrador."))
    return begin_login(user, session.pop("sso_next", None))


def configurar_totp():
    user = get_preauth_user()
    if user is None:
        return redirect(url_for("login"))
    if not requires_totp(user["role"]):
        return establish_login(user, session.get("preauth_next"))

    if user["totp_enabled"]:
        return redirect(url_for("verificar_totp"))
    db = get_db()
    secret = user["totp_pending_secret"]
    if not secret:
        secret = pyotp.random_base32()
        db.execute("UPDATE users SET totp_pending_secret = ? WHERE id = ?", (secret, user["id"]))
        db.commit()

    if request.method == "POST":
        code = request.form.get("code", "").replace(" ", "").strip()
        if not pyotp.TOTP(secret).verify(code, valid_window=1):
            return render_template(
                "totp_setup.html",
                username=user["username"],
                secret=secret,
                error="Código inválido. Verifique o aplicativo e tente novamente.",
            ), 400
        db.execute(
            """
            UPDATE users
            SET totp_secret = ?, totp_pending_secret = NULL, totp_enabled = 1
            WHERE id = ?
            """,
            (secret, user["id"]),
        )
        db.commit()
        log_user_audit("totp_ativado", "Autenticação TOTP ativada.", user["id"], user["company_id"])
        return establish_login(user, session.get("preauth_next"))

    return render_template(
        "totp_setup.html", username=user["username"], secret=secret, error=None
    )


def verificar_totp():
    user = get_preauth_user()
    if user is None:
        return redirect(url_for("login"))
    if not requires_totp(user["role"]):
        return establish_login(user, session.get("preauth_next"))
    if not user["totp_enabled"] or not user["totp_secret"]:
        return redirect(url_for("configurar_totp"))

    if request.method == "POST":
        code = request.form.get("code", "").replace(" ", "").strip()
        if pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            return establish_login(user, session.get("preauth_next"))
        attempts = session.get("totp_attempts", 0) + 1
        if attempts >= 5:
            session.clear()
            return redirect(url_for("login", error="Muitas tentativas inválidas. Entre novamente."))
        session["totp_attempts"] = attempts
        return render_template("totp_verify.html", error="Código inválido. Tente novamente."), 400

    return render_template("totp_verify.html", error=None)


def primeiro_acesso():
    if request.method == "GET":
        db = get_db()
        companies = db.execute("SELECT name FROM companies ORDER BY name").fetchall()
        return render_template(
            "primeiro_acesso.html",
            roles=SELF_REGISTRATION_ROLES,
            companies=companies,
            error=None,
        )

    username = request.form.get("username", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()
    company_name = request.form.get("company_name", "").strip()
    cpf = normalize_cpf(request.form.get("cpf", ""))
    company_cnpj = normalize_cnpj(request.form.get("company_cnpj", ""))
    db = get_db()
    companies = db.execute("SELECT name FROM companies ORDER BY name").fetchall()

    error = None
    if not re.fullmatch(r"[a-z0-9._-]{3,50}", username):
        error = "O login deve ter de 3 a 50 caracteres: letras, números, ponto, hífen ou sublinhado."
    elif len(full_name) < 2 or len(full_name) > 120:
        error = "Informe seu nome completo."
    elif cpf is None:
        error = "CPF inválido. Verifique os dígitos."
    elif role == "cliente" and company_cnpj is None:
        error = "CNPJ inválido. Verifique os dígitos."
    elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        error = "Informe um e-mail válido."
    elif role not in SELF_REGISTRATION_ROLES:
        error = "Selecione um tipo de conta válido."
    elif role == "cliente" and not company_name:
        error = "Informe o nome da empresa."
    elif len(company_name) > 150:
        error = "O nome da empresa deve ter até 150 caracteres."
    elif role == "cliente" and db.execute(
        """
        SELECT 1 FROM companies
        WHERE lower(name) = lower(?) AND cnpj IS NOT NULL AND cnpj != ?
        """,
        (company_name, format_cnpj(company_cnpj)),
    ).fetchone():
        error = "O CNPJ informado não corresponde ao cadastrado para esta empresa."
    elif role == "cliente" and db.execute(
        """
        SELECT 1 FROM companies
        WHERE cnpj = ? AND lower(name) != lower(?)
        """,
        (format_cnpj(company_cnpj), company_name),
    ).fetchone():
        error = "CNPJ já cadastrado. Verifique se a empresa já existe."
    elif len(password) < 8:
        error = "A senha deve ter pelo menos 8 caracteres."
    elif db.execute("SELECT 1 FROM users WHERE lower(username) = ?", (username,)).fetchone():
        error = "Não foi possível enviar. Verifique os dados ou entre em contato com o administrador."
    elif db.execute(
        "SELECT 1 FROM access_requests WHERE (lower(username) = ? OR lower(email) = ?) AND status = 'pendente'",
        (username, email),
    ).fetchone():
        error = "Já existe uma solicitação pendente para este login ou e-mail."
    else:
        try:
            encrypted_cpf, cpf_lookup = protect_cpf(cpf)
        except IdentityConfigurationError as configuration_error:
            return render_template(
                "primeiro_acesso.html",
                roles=SELF_REGISTRATION_ROLES,
                companies=companies,
                error=str(configuration_error),
            ), 503
        if db.execute("SELECT 1 FROM users WHERE cpf_lookup = ?", (cpf_lookup,)).fetchone():
            error = "CPF já cadastrado. Fale com o administrador."
        elif db.execute(
            "SELECT 1 FROM access_requests WHERE cpf_lookup = ? AND status = 'pendente'",
            (cpf_lookup,),
        ).fetchone():
            error = "Já existe uma solicitação pendente para este CPF."

    if error:
        return render_template("primeiro_acesso.html", roles=SELF_REGISTRATION_ROLES, companies=companies, error=error), 400

    db.execute(
        """
        INSERT INTO access_requests
            (username, password_hash, full_name, role, email, company_name,
             cpf_ciphertext, cpf_lookup, company_cnpj)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username, generate_password_hash(password), full_name, role, email,
            company_name or None, encrypted_cpf, cpf_lookup, company_cnpj,
        ),
    )
    db.commit()
    return render_template("primeiro_acesso.html", roles=SELF_REGISTRATION_ROLES, companies=companies, submitted=True)


def esqueci_senha():
    if request.method == "POST":
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        db = get_db()
        user = db.execute(
            """
            SELECT id FROM users
            WHERE lower(username) = ?
              AND (? = '' OR lower(COALESCE(email, '')) = ?)
            """,
            (username, email, email),
        ).fetchone()
        if user:
            pending = db.execute(
                "SELECT 1 FROM password_reset_requests WHERE lower(username) = ? AND status = 'pendente'",
                (username,),
            ).fetchone()
            if not pending:
                db.execute(
                    "INSERT INTO password_reset_requests (username, email) VALUES (?, ?)",
                    (username, email or None),
                )
                db.commit()
        return render_template("esqueci_senha.html", submitted=True)
    return render_template("esqueci_senha.html", submitted=False)


def logout():
    session.clear()
    return redirect(url_for("login"))


def register_routes(app):
    app.add_url_rule('/login', view_func=login, endpoint='login', methods=['GET', 'POST'])
    app.add_url_rule('/login/<provider>', view_func=sso_login, endpoint='sso_login')
    app.add_url_rule('/login/<provider>/callback', view_func=sso_callback, endpoint='sso_callback')
    app.add_url_rule('/2fa/configurar', view_func=configurar_totp, endpoint='configurar_totp', methods=['GET', 'POST'])
    app.add_url_rule('/2fa/verificar', view_func=verificar_totp, endpoint='verificar_totp', methods=['GET', 'POST'])
    app.add_url_rule('/cadastro/completar-cpf', view_func=completar_cadastro_cpf, endpoint='completar_cadastro_cpf', methods=['GET', 'POST'])
    app.add_url_rule('/primeiro-acesso', view_func=primeiro_acesso, endpoint='primeiro_acesso', methods=['GET', 'POST'])
    app.add_url_rule('/esqueci-senha', view_func=esqueci_senha, endpoint='esqueci_senha', methods=['GET', 'POST'])
    app.add_url_rule('/logout', view_func=logout, endpoint='logout')
