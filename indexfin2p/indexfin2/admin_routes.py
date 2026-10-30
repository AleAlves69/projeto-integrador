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

@login_required
@role_required("admin")
def revisar_acesso(request_id):
    action = request.form.get("action", "").strip()
    if action not in {"aprovar", "recusar"}:
        return render_user_management("Ação de aprovação inválida.", 400)
    db = get_db()
    access_request = db.execute(
        "SELECT * FROM access_requests WHERE id = ? AND status = 'pendente'",
        (request_id,),
    ).fetchone()
    if access_request is None:
        return render_user_management("Solicitação não encontrada ou já analisada.", 404)
    if action == "aprovar":
        if not access_request["cpf_ciphertext"] or not access_request["cpf_lookup"]:
            return render_user_management(
                "Este cadastro foi enviado antes da exigência de CPF. Peça à pessoa para enviar uma nova solicitação.",
                409,
            )
        if db.execute(
            "SELECT 1 FROM users WHERE lower(username) = ?",
            (access_request["username"].lower(),),
        ).fetchone():
            return render_user_management("Este login já foi utilizado; a solicitação não pode ser aprovada.", 409)
        if db.execute(
            "SELECT 1 FROM users WHERE cpf_lookup = ?",
            (access_request["cpf_lookup"],),
        ).fetchone():
            return render_user_management("Este CPF já foi cadastrado em outra conta; a solicitação não pode ser aprovada.", 409)
        company_id = None
        if access_request["role"] == "cliente":
            if not access_request["company_cnpj"]:
                return render_user_management(
                    "A solicitação não contém um CNPJ válido. Peça à pessoa para enviar uma nova solicitação.",
                    409,
                )
            company = db.execute(
                "SELECT id, cnpj FROM companies WHERE lower(name) = lower(?) ORDER BY id LIMIT 1",
                (access_request["company_name"],),
            ).fetchone()
            if company:
                requested_cnpj = format_cnpj(access_request["company_cnpj"])
                if company["cnpj"] and company["cnpj"] != requested_cnpj:
                    return render_user_management(
                        "O CNPJ informado não corresponde ao cadastrado para esta empresa. Verifique com o administrador.",
                        409,
                    )
                if db.execute(
                    "SELECT 1 FROM companies WHERE cnpj = ? AND id != ?",
                    (requested_cnpj, company["id"]),
                ).fetchone():
                    return render_user_management("CNPJ já cadastrado em outra empresa.", 409)
                company_id = company["id"]
                if not company["cnpj"]:
                    db.execute(
                        "UPDATE companies SET cnpj = ? WHERE id = ?",
                        (requested_cnpj, company_id),
                    )
            else:
                if db.execute(
                    "SELECT 1 FROM companies WHERE cnpj = ?",
                    (format_cnpj(access_request["company_cnpj"]),),
                ).fetchone():
                    return render_user_management("CNPJ já cadastrado em outra empresa.", 409)
                company_id = db.execute(
                    "INSERT INTO companies (name, cnpj) VALUES (?, ?)",
                    (access_request["company_name"], format_cnpj(access_request["company_cnpj"])),
                ).lastrowid
        cursor = db.execute(
            """
            INSERT INTO users
                (username, password_hash, full_name, role, email, cpf_ciphertext, cpf_lookup, company_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                access_request["username"],
                access_request["password_hash"],
                access_request["full_name"],
                access_request["role"],
                access_request["email"],
                access_request["cpf_ciphertext"],
                access_request["cpf_lookup"],
                company_id,
            ),
        )
        user_id = cursor.lastrowid
    else:
        company_id = None
        user_id = None

    db.execute(
        """
        UPDATE access_requests
        SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewed_by = ?,
            cpf_ciphertext = NULL, cpf_lookup = NULL
        WHERE id = ?
        """,
        ("aprovada" if action == "aprovar" else "recusada", session["user_id"], request_id),
    )
    db.commit()
    log_user_audit(
        "cadastro_aprovado" if action == "aprovar" else "cadastro_recusado",
        f"Solicitação de acesso de '{access_request['username']}' foi {action}.",
        user_id,
        company_id,
    )
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def dispensar_recuperacao_senha(request_id):
    db = get_db()
    result = db.execute(
        """
        UPDATE password_reset_requests
        SET status = 'dispensada', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
        WHERE id = ? AND status = 'pendente'
        """,
        (session["user_id"], request_id),
    )
    if result.rowcount == 0:
        return render_user_management("Solicitação de recuperação não encontrada ou já analisada.", 404)
    db.commit()
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def usuarios():
    if request.method == "GET":
        return render_user_management()

    username = request.form.get("username", "").strip().lower()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "").strip()
    cpf = normalize_cpf(request.form.get("cpf", ""))
    company_value = request.form.get("company_id", "").strip()
    company_id = request.form.get("company_id", type=int) if company_value else None

    if not re.fullmatch(r"[a-z0-9._-]{3,50}", username):
        return render_user_management("Login: use de 3 a 50 caracteres (letras, números, ponto, hífen ou sublinhado).", 400)
    if len(full_name) < 2 or role not in AVAILABLE_ROLES or len(password) < 8:
        return render_user_management("Informe nome, papel válido e senha inicial com pelo menos 8 caracteres.", 400)
    if cpf is None:
        return render_user_management("CPF inválido. Verifique os dígitos.", 400)
    if role == "admin" and request.form.get("confirm_admin") != "sim":
        return render_user_management("Confirme explicitamente a criação de uma conta administradora.", 400)
    if company_value and (company_id is None or not valid_company_id(company_id)):
        return render_user_management("Selecione uma empresa válida.", 400)
    if role in {"cliente", "fornecedor"} and company_id is None:
        return render_user_management("Vincule o cliente ou fornecedor a uma empresa.", 400)

    db = get_db()
    if role in {"cliente", "fornecedor"}:
        company = db.execute("SELECT cnpj FROM companies WHERE id = ?", (company_id,)).fetchone()
        if company is None or not company["cnpj"]:
            return render_user_management(
                "Cadastre um CNPJ válido para a empresa antes de criar a conta de cliente ou fornecedor.",
                400,
            )
    if db.execute("SELECT 1 FROM users WHERE lower(username) = ?", (username,)).fetchone():
        return render_user_management("Este login já está cadastrado.", 409)
    try:
        cpf_ciphertext, cpf_lookup = protect_cpf(cpf)
    except IdentityConfigurationError as error:
        return render_user_management(str(error), 503)
    if db.execute("SELECT 1 FROM users WHERE cpf_lookup = ?", (cpf_lookup,)).fetchone():
        return render_user_management("CPF já cadastrado. Fale com o administrador.", 409)
    if db.execute(
        "SELECT 1 FROM access_requests WHERE cpf_lookup = ? AND status = 'pendente'",
        (cpf_lookup,),
    ).fetchone():
        return render_user_management("Este CPF pertence a um cadastro pendente.", 409)
    cursor = db.execute(
        """
        INSERT INTO users
            (username, password_hash, full_name, role, email, cpf_ciphertext, cpf_lookup, company_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            username, generate_password_hash(password), full_name, role, email or None,
            cpf_ciphertext, cpf_lookup, company_id,
        ),
    )
    db.commit()
    log_user_audit("usuario_criado", f"Conta '{username}' criada com papel '{role}'.", cursor.lastrowid, company_id)
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def criar_empresa():
    name = request.form.get("name", "").strip()
    cnpj = normalize_cnpj(request.form.get("cnpj", ""))
    if len(name) < 2:
        return render_user_management("Informe o nome da empresa.", 400)
    if cnpj is None:
        return render_user_management("CNPJ inválido. Verifique os dígitos.", 400)
    db = get_db()
    if db.execute("SELECT 1 FROM companies WHERE lower(name) = lower(?)", (name,)).fetchone():
        return render_user_management("Esta empresa já está cadastrada.", 409)
    if db.execute("SELECT 1 FROM companies WHERE cnpj = ?", (format_cnpj(cnpj),)).fetchone():
        return render_user_management("CNPJ já cadastrado. Verifique se a empresa já existe.", 409)
    company_id = db.execute(
        "INSERT INTO companies (name, cnpj) VALUES (?, ?)",
        (name, format_cnpj(cnpj)),
    ).lastrowid
    db.commit()
    log_user_audit("empresa_criada", f"Empresa '{name}' cadastrada.", company_id=company_id)
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def editar_empresa(company_id):
    db = get_db()
    company = db.execute("SELECT id, name FROM companies WHERE id = ?", (company_id,)).fetchone()
    if company is None:
        return "Empresa não encontrada.", 404
    cnpj = normalize_cnpj(request.form.get("cnpj", ""))
    if cnpj is None:
        return render_user_management("CNPJ inválido. Verifique os dígitos.", 400)
    formatted_cnpj = format_cnpj(cnpj)
    if db.execute(
        "SELECT 1 FROM companies WHERE cnpj = ? AND id != ?",
        (formatted_cnpj, company_id),
    ).fetchone():
        return render_user_management("CNPJ já cadastrado. Verifique se a empresa já existe.", 409)
    db.execute("UPDATE companies SET cnpj = ? WHERE id = ?", (formatted_cnpj, company_id))
    db.commit()
    log_user_audit("cnpj_empresa_atualizado", f"CNPJ da empresa '{company['name']}' atualizado.", company_id=company_id)
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def criar_fornecedor():
    name = request.form.get("name", "").strip()
    cnpj = normalize_cnpj(request.form.get("cnpj", ""))
    category = request.form.get("category", "").strip()
    if len(name) < 2:
        return render_user_management("Informe o nome do fornecedor.", 400)
    if cnpj is None:
        return render_user_management("CNPJ inválido. Verifique os dígitos.", 400)
    db = get_db()
    if db.execute("SELECT 1 FROM suppliers WHERE lower(name) = lower(?)", (name,)).fetchone():
        return render_user_management("Este fornecedor já está cadastrado.", 409)
    if db.execute("SELECT 1 FROM suppliers WHERE cnpj = ?", (format_cnpj(cnpj),)).fetchone():
        return render_user_management("CNPJ já cadastrado em outro fornecedor.", 409)
    supplier_id = db.execute(
        "INSERT INTO suppliers (name, cnpj, category) VALUES (?, ?, ?)",
        (name, format_cnpj(cnpj), category or None),
    ).lastrowid
    db.commit()
    log_user_audit("fornecedor_criado", f"Fornecedor '{name}' cadastrado.")
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def editar_fornecedor(supplier_id):
    db = get_db()
    supplier = db.execute("SELECT id, name FROM suppliers WHERE id = ?", (supplier_id,)).fetchone()
    if supplier is None:
        return "Fornecedor não encontrado.", 404
    cnpj = normalize_cnpj(request.form.get("cnpj", ""))
    if cnpj is None:
        return render_user_management("CNPJ inválido. Verifique os dígitos.", 400)
    formatted_cnpj = format_cnpj(cnpj)
    if db.execute(
        "SELECT 1 FROM suppliers WHERE cnpj = ? AND id != ?",
        (formatted_cnpj, supplier_id),
    ).fetchone():
        return render_user_management("CNPJ já cadastrado em outro fornecedor.", 409)
    db.execute("UPDATE suppliers SET cnpj = ? WHERE id = ?", (formatted_cnpj, supplier_id))
    db.commit()
    log_user_audit("cnpj_fornecedor_atualizado", f"CNPJ do fornecedor '{supplier['name']}' atualizado.")
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def editar_usuario(user_id):
    db = get_db()
    user = db.execute("SELECT id, username, role, company_id, active FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "Usuário não encontrado.", 404
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "").strip()
    role_reason = request.form.get("role_reason", "").strip()
    cpf_input = request.form.get("cpf", "").strip()
    cpf_reason = request.form.get("cpf_reason", "").strip()
    company_value = request.form.get("company_id", "").strip()
    company_id = request.form.get("company_id", type=int) if company_value else None
    if len(full_name) < 2 or role not in AVAILABLE_ROLES:
        return render_user_management("Informe nome e papel válidos.", 400)
    if company_value and (company_id is None or not valid_company_id(company_id)):
        return render_user_management("Selecione uma empresa válida.", 400)
    if role in {"cliente", "fornecedor"} and company_id is None:
        return render_user_management("Vincule o cliente ou fornecedor a uma empresa.", 400)
    if role in {"cliente", "fornecedor"} and (
        role != user["role"] or company_id != user["company_id"]
    ):
        company = db.execute("SELECT cnpj FROM companies WHERE id = ?", (company_id,)).fetchone()
        if company is None or not company["cnpj"]:
            return render_user_management(
                "Cadastre um CNPJ válido para a empresa antes de vincular a conta.",
                400,
            )
    cpf_values = (None, None)
    if cpf_input:
        cpf = normalize_cpf(cpf_input)
        if cpf is None:
            return render_user_management("CPF inválido. Verifique os dígitos.", 400)
        if not cpf_reason:
            return render_user_management("Informe a justificativa para alterar o CPF.", 400)
        try:
            cpf_values = protect_cpf(cpf)
        except IdentityConfigurationError as error:
            return render_user_management(str(error), 503)
        if db.execute(
            "SELECT 1 FROM users WHERE cpf_lookup = ? AND id != ?",
            (cpf_values[1], user_id),
        ).fetchone():
            return render_user_management("CPF já cadastrado. Fale com o administrador.", 409)
        if db.execute(
            "SELECT 1 FROM access_requests WHERE cpf_lookup = ? AND status = 'pendente'",
            (cpf_values[1],),
        ).fetchone():
            return render_user_management("Este CPF pertence a um cadastro pendente.", 409)
    if role != user["role"] and not role_reason:
        return render_user_management("Informe a justificativa para alterar o papel do usuário.", 400)
    if role == "admin" and user["role"] != "admin" and request.form.get("confirm_admin") != "sim":
        return render_user_management("Confirme explicitamente a promoção para administrador.", 400)
    if is_last_active_admin(user, new_role=role):
        return render_user_management("Não é permitido remover o último administrador ativo.", 409)

    if cpf_input:
        db.execute(
            """
            UPDATE users
            SET full_name = ?, email = ?, role = ?, company_id = ?,
                cpf_ciphertext = ?, cpf_lookup = ?
            WHERE id = ?
            """,
            (full_name, email or None, role, company_id, *cpf_values, user_id),
        )
    else:
        db.execute(
            "UPDATE users SET full_name = ?, email = ?, role = ?, company_id = ? WHERE id = ?",
            (full_name, email or None, role, company_id, user_id),
        )
    db.commit()
    log_user_audit(
        "usuario_editado",
        f"Dados e permissões de '{user['username']}' atualizados (papel: {role}). Justificativa: {role_reason or 'não se aplica'}. Justificativa CPF: {cpf_reason or 'não se aplica'}.",
        user_id,
        company_id,
    )
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def alterar_status_usuario(user_id):
    db = get_db()
    user = db.execute(
        "SELECT id, username, role, company_id, active FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if user is None:
        return "Usuário não encontrado.", 404
    action = request.form.get("action", "").strip()
    reason = request.form.get("reason", "").strip()
    if action not in {"ativar", "inativar"}:
        return render_user_management("Ação de status inválida.", 400)
    if action == "inativar" and not reason:
        return render_user_management("Informe o motivo para inativar a conta.", 400)
    active = action == "ativar"
    if user_id == session.get("user_id") and not active:
        return render_user_management("Você não pode inativar sua própria conta.", 409)
    if is_last_active_admin(user, new_active=active):
        return render_user_management("Não é permitido inativar o último administrador ativo.", 409)

    db.execute("UPDATE users SET active = ? WHERE id = ?", (int(active), user_id))
    db.commit()
    log_user_audit(
        "usuario_ativado" if active else "usuario_inativado",
        f"Conta '{user['username']}' {'ativada' if active else 'inativada'}. Motivo: {reason or 'reativação administrativa'}.",
        user_id,
        user["company_id"],
    )
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def redefinir_senha_usuario(user_id):
    password = request.form.get("password", "")
    if len(password) < 8:
        return render_user_management("A nova senha precisa ter pelo menos 8 caracteres.", 400)
    db = get_db()
    user = db.execute("SELECT id, username, company_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "Usuário não encontrado.", 404
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(password), user_id),
    )
    db.execute(
        """
        UPDATE password_reset_requests
        SET status = 'resolvida', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
        WHERE lower(username) = lower(?) AND status = 'pendente'
        """,
        (session["user_id"], user["username"]),
    )
    db.commit()
    log_user_audit("senha_redefinida", f"Senha de '{user['username']}' redefinida pelo administrador.", user_id, user["company_id"])
    return redirect(url_for("usuarios"))


@login_required
@role_required("admin")
def redefinir_totp_usuario(user_id):
    db = get_db()
    user = db.execute("SELECT id, username, role, company_id FROM users WHERE id = ?", (user_id,)).fetchone()
    if user is None:
        return "Usuário não encontrado.", 404
    if not requires_totp(user["role"]):
        return render_user_management("O papel deste usuário não exige TOTP.", 400)
    db.execute(
        """
        UPDATE users
        SET totp_secret = NULL, totp_pending_secret = NULL, totp_enabled = 0
        WHERE id = ?
        """,
        (user_id,),
    )
    db.commit()
    log_user_audit("totp_redefinido", f"TOTP de '{user['username']}' redefinido pelo administrador.", user_id, user["company_id"])
    if user_id == session.get("user_id"):
        session.clear()
        session["preauth_user_id"] = user_id
        session["preauth_next"] = url_for("dashboard")
        return redirect(url_for("configurar_totp"))
    return redirect(url_for("usuarios"))


def register_routes(app):
    app.add_url_rule('/usuarios/acessos/<int:request_id>', view_func=revisar_acesso, endpoint='revisar_acesso', methods=['POST'])
    app.add_url_rule('/usuarios/recuperacoes/<int:request_id>/dispensar', view_func=dispensar_recuperacao_senha, endpoint='dispensar_recuperacao_senha', methods=['POST'])
    app.add_url_rule('/usuarios', view_func=usuarios, endpoint='usuarios', methods=['GET', 'POST'])
    app.add_url_rule('/empresas', view_func=criar_empresa, endpoint='criar_empresa', methods=['POST'])
    app.add_url_rule('/empresas/<int:company_id>', view_func=editar_empresa, endpoint='editar_empresa', methods=['POST'])
    app.add_url_rule('/fornecedores', view_func=criar_fornecedor, endpoint='criar_fornecedor', methods=['POST'])
    app.add_url_rule('/fornecedores/<int:supplier_id>', view_func=editar_fornecedor, endpoint='editar_fornecedor', methods=['POST'])
    app.add_url_rule('/usuarios/<int:user_id>/editar', view_func=editar_usuario, endpoint='editar_usuario', methods=['POST'])
    app.add_url_rule('/usuarios/<int:user_id>/status', view_func=alterar_status_usuario, endpoint='alterar_status_usuario', methods=['POST'])
    app.add_url_rule('/usuarios/<int:user_id>/senha', view_func=redefinir_senha_usuario, endpoint='redefinir_senha_usuario', methods=['POST'])
    app.add_url_rule('/usuarios/<int:user_id>/totp/reset', view_func=redefinir_totp_usuario, endpoint='redefinir_totp_usuario', methods=['POST'])
