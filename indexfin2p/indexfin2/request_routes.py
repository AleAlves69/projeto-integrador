import re
import sqlite3

import pyotp
from flask import current_app, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from .database import get_db
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
def solicitacoes():
    db = get_db()
    current_user = get_current_user()
    company_filter = ""
    params = ()
    if normalize_role(current_user["role"]) == "cliente":
        company_filter = "WHERE r.company_id = ?"
        params = (current_user["company_id"],)
    rows = db.execute(
        f"""
        SELECT r.*, c.name AS company_name,
               (SELECT COUNT(*) FROM quotes q WHERE q.request_id = r.id) AS total_quotes,
               (SELECT COALESCE(MAX(b.final_total), 0) FROM budgets b WHERE b.request_id = r.id) AS final_total
        FROM requests r
        LEFT JOIN companies c ON c.id = r.company_id
        {company_filter}
        ORDER BY r.id DESC
        """,
        params,
    ).fetchall()
    return render_template("solicitacoes.html", current_user=current_user, requests=rows)


@login_required
@role_required("admin", "operador")
def nova_solicitacao():
    db = get_db()
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        client_name = request.form.get("client_name", "").strip()
        company_id = request.form.get("company_id", type=int)
        initial_budget = float(request.form.get("initial_budget", 0) or 0)
        status = request.form.get("status", "em cotação")

        if not title or not client_name or not company_id:
            companies = db.execute("SELECT * FROM companies ORDER BY name").fetchall()
            return render_template("nova_solicitacao.html", current_user=get_current_user(), companies=companies, error="Preencha todos os campos obrigatórios.")

        request_id = db.execute(
            """
            INSERT INTO requests (title, client_name, company_id, initial_budget, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (title, client_name, company_id, initial_budget, status, session.get("full_name", "Operador")),
        ).lastrowid

        for idx in range(1, 4):
            description = request.form.get(f"item_{idx}_description", "").strip()
            quantity = request.form.get(f"item_{idx}_quantity", "").strip()
            unit = request.form.get(f"item_{idx}_unit", "un").strip() or "un"
            estimated_unit_price = request.form.get(f"item_{idx}_unit_price", "").strip()
            if not description or not quantity:
                continue
            db.execute(
                """
                INSERT INTO request_items (request_id, description, quantity, unit, estimated_unit_price)
                VALUES (?, ?, ?, ?, ?)
                """,
                (request_id, description, float(quantity), unit, float(estimated_unit_price or 0)),
            )

        db.commit()
        return redirect(url_for("detalhe_solicitacao", request_id=request_id))

    companies = db.execute("SELECT * FROM companies ORDER BY name").fetchall()
    return render_template("nova_solicitacao.html", current_user=get_current_user(), companies=companies)


@login_required
def detalhe_solicitacao(request_id):
    request_row = get_request_by_id(request_id)
    if request_row is None:
        return "Solicitação não encontrada.", 404
    if not can_access_request(get_current_user(), request_row):
        return "Solicitação não encontrada.", 404

    items = get_request_items(request_id)
    quotes = get_quotes_for_request(request_id)
    budget = get_budget_for_request(request_id)
    quote_comparison = get_quote_comparison(request_id)
    approval_requirement = get_approval_requirement(request_row, budget)
    audit_logs = db = get_db().execute(
        """
        SELECT *
        FROM audit_logs
        WHERE request_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (request_id,),
    ).fetchall()

    return render_template(
        "solicitacao_detail.html",
        current_user=get_current_user(),
        request=request_row,
        items=items,
        quotes=quotes,
        budget=budget,
        quote_comparison=quote_comparison,
        approval_requirement=approval_requirement,
        audit_logs=audit_logs,
    )


@login_required
@role_required("admin", "operador")
def nova_cotacao(request_id):
    db = get_db()
    request_row = get_request_by_id(request_id)
    if request_row is None:
        return "Solicitação não encontrada.", 404

    suppliers = db.execute("SELECT * FROM suppliers ORDER BY name").fetchall()

    if request.method == "POST":
        supplier_id = request.form.get("supplier_id", type=int)
        total = float(request.form.get("total", 0) or 0)
        lead_time_days = request.form.get("lead_time_days", type=int) or 0
        payment_terms = request.form.get("payment_terms", "").strip()
        notes = request.form.get("notes", "").strip()

        if not supplier_id:
            return render_template("nova_cotacao.html", current_user=get_current_user(), request=request_row, suppliers=suppliers, error="Selecione um fornecedor."), 400
        supplier = db.execute(
            "SELECT cnpj FROM suppliers WHERE id = ?",
            (supplier_id,),
        ).fetchone()
        if supplier is None or not supplier["cnpj"]:
            return render_template(
                "nova_cotacao.html",
                current_user=get_current_user(),
                request=request_row,
                suppliers=suppliers,
                error="O fornecedor ainda não tem CNPJ cadastrado. Fale com o administrador.",
            ), 400

        quote_id = db.execute(
            """
            INSERT INTO quotes (request_id, supplier_id, total, lead_time_days, payment_terms, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (request_id, supplier_id, total, lead_time_days, payment_terms, notes),
        ).lastrowid

        for idx in range(1, 4):
            description = request.form.get(f"item_{idx}_description", "").strip()
            quantity = request.form.get(f"item_{idx}_quantity", "").strip()
            unit = request.form.get(f"item_{idx}_unit", "un").strip() or "un"
            unit_price = request.form.get(f"item_{idx}_unit_price", "").strip()
            if not description or not quantity:
                continue
            db.execute(
                """
                INSERT INTO quote_items (quote_id, description, quantity, unit, unit_price)
                VALUES (?, ?, ?, ?, ?)
                """,
                (quote_id, description, float(quantity), unit, float(unit_price or 0)),
            )

        db.commit()
        set_request_status(request_id, "em cotação", session.get("full_name", "Sistema"), "nova_cotacao")
        log_audit(request_id, "cotacao_recebida", f"Nova cotação registrada para o fornecedor ID {supplier_id}.", session.get("full_name", "Sistema"))
        return redirect(url_for("detalhe_solicitacao", request_id=request_id))

    return render_template("nova_cotacao.html", current_user=get_current_user(), request=request_row, suppliers=suppliers)


@login_required
@role_required("admin", "operador")
def criar_orcamento(request_id):
    db = get_db()
    request_row = get_request_by_id(request_id)
    if request_row is None:
        return "Solicitação não encontrada.", 404

    quote_id = request.form.get("quote_id", type=int)
    final_total = float(request.form.get("final_total", 0) or 0)
    validity_days = request.form.get("validity_days", type=int) or 15
    budget_status = request.form.get("status", "enviado")
    notes = request.form.get("notes", "").strip()

    if not quote_id:
        return "Selecione uma cotação antes de gerar o orçamento.", 400

    if final_total <= 0:
        return "Informe um valor final maior que zero para o orçamento.", 400

    if final_total > float(request_row["initial_budget"]) and normalize_role(session.get("role")) == "operador":
        return "Orçamento acima do valor inicial exige aprovação administrativa antes da liberação final.", 403

    db.execute(
        """
        INSERT INTO budgets (request_id, quote_id, final_total, validity_days, status, notes)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (request_id, quote_id, final_total, validity_days, budget_status, notes),
    )
    db.commit()

    approval_requirement = get_approval_requirement(request_row, {"final_total": final_total})
    request_status = "orcamento enviado"
    if approval_requirement:
        request_status = approval_requirement["stage"]

    if final_total > float(request_row["initial_budget"]):
        log_audit(
            request_id,
            "orcamento_aguardando_aprovacao",
            f"Orçamento de R$ {final_total:.2f} foi registrado, mas excede o valor inicial e aguarda aprovação administrativa.",
            session.get("full_name", "Sistema"),
        )
    else:
        log_audit(
            request_id,
            "orcamento_registrado",
            f"Orçamento de R$ {final_total:.2f} registrado para a cotação #{quote_id} com validade de {validity_days} dias.",
            session.get("full_name", "Sistema"),
        )

    set_request_status(request_id, request_status, session.get("full_name", "Sistema"), "orcamento_registrado")

    return redirect(url_for("detalhe_solicitacao", request_id=request_id))


@login_required
@role_required("admin", "cliente")
def aprovar_solicitacao(request_id):
    request_row = get_request_by_id(request_id)
    if request_row is None:
        return "Solicitação não encontrada.", 404
    if not can_access_request(get_current_user(), request_row):
        return "Solicitação não encontrada.", 404

    budget = get_budget_for_request(request_id)
    if budget is None:
        return "É necessário registrar um orçamento antes da aprovação final.", 400

    approval_requirement = get_approval_requirement(request_row, budget)
    if approval_requirement is None:
        return "Não foi possível determinar a etapa de aprovação deste orçamento.", 400

    action = request.form.get("action", "").strip()
    if action not in {"aprovar", "rejeitar"}:
        return "Ação de aprovação inválida.", 400

    user = get_current_user()
    required_role = approval_requirement["required_role"]
    if action == "aprovar":
        if float(budget["final_total"]) > float(request_row["initial_budget"]) and user["role"] != "admin":
            return "Orçamentos acima do valor inicial exigem aprovação de administrador.", 403
        if float(budget["final_total"]) <= float(request_row["initial_budget"]) and user["role"] not in {"cliente", "admin"}:
            return (f"A etapa atual exige aprovação de {required_role} antes do avanço do processo.", 403)
        new_status = "aprovado"
        action_label = "aprovacao_aprovada"
        detail = f"Solicitação aprovada por {user['full_name']} ({user['role']}) com orçamento final de R$ {float(budget['final_total']):.2f}."
    else:
        new_status = "recusado"
        action_label = "aprovacao_rejeitada"
        detail = f"Solicitação recusada por {user['full_name']} ({user['role']}) com orçamento final de R$ {float(budget['final_total']):.2f}."

    set_request_status(request_id, new_status, user["full_name"], action_label)
    log_audit(request_id, action_label, detail, user["full_name"])
    return redirect(url_for("detalhe_solicitacao", request_id=request_id))


def register_routes(app):
    app.add_url_rule('/solicitacoes', view_func=solicitacoes, endpoint='solicitacoes')
    app.add_url_rule('/solicitacoes/nova', view_func=nova_solicitacao, endpoint='nova_solicitacao', methods=['GET', 'POST'])
    app.add_url_rule('/solicitacoes/<int:request_id>', view_func=detalhe_solicitacao, endpoint='detalhe_solicitacao')
    app.add_url_rule('/solicitacoes/<int:request_id>/cotacao', view_func=nova_cotacao, endpoint='nova_cotacao', methods=['GET', 'POST'])
    app.add_url_rule('/solicitacoes/<int:request_id>/orcamento', view_func=criar_orcamento, endpoint='criar_orcamento', methods=['POST'])
    app.add_url_rule('/solicitacoes/<int:request_id>/aprovacao', view_func=aprovar_solicitacao, endpoint='aprovar_solicitacao', methods=['POST'])
