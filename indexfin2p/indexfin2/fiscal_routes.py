import re
import sqlite3

from flask import redirect, render_template, request, session, url_for

from .database import get_db
from .identity import format_cnpj, normalize_cnpj
from .security import get_current_user, login_required
from .services import log_audit

FISCAL_ROLES = {"admin", "operador_financeiro"}
TAX_REGIMES = {"simples_nacional", "lucro_presumido", "lucro_real", "mei"}


def _can_manage_fiscal(user):
    return user is not None and user["role"] in FISCAL_ROLES


def _render_fiscal(error=None, status=200):
    db = get_db()
    issuers = db.execute(
        "SELECT * FROM fiscal_issuers ORDER BY legal_name COLLATE NOCASE, id"
    ).fetchall()
    drafts = db.execute(
        """
        SELECT d.*, r.title AS request_title
        FROM fiscal_drafts d
        JOIN requests r ON r.id = d.request_id
        ORDER BY d.id DESC
        """
    ).fetchall()
    eligible_requests = db.execute(
        """
        SELECT r.id, r.title, r.client_name, c.name AS company_name, c.cnpj,
               b.id AS budget_id, b.final_total
        FROM requests r
        JOIN companies c ON c.id = r.company_id
        JOIN budgets b ON b.id = (
            SELECT id FROM budgets WHERE request_id = r.id ORDER BY id DESC LIMIT 1
        )
        WHERE r.status = 'aprovado' AND c.cnpj IS NOT NULL
        ORDER BY r.id DESC
        """
    ).fetchall()
    return render_template(
        "fiscal.html",
        current_user=get_current_user(),
        issuers=issuers,
        drafts=drafts,
        eligible_requests=eligible_requests,
        error=error,
    ), status


@login_required
def fiscal_page():
    if not _can_manage_fiscal(get_current_user()):
        return render_template("forbidden.html", user=get_current_user()), 403
    return _render_fiscal()


@login_required
def create_fiscal_issuer():
    user = get_current_user()
    if user is None or user["role"] != "admin":
        return render_template("forbidden.html", user=user), 403

    form = request.form
    legal_name = form.get("legal_name", "").strip()
    cnpj = normalize_cnpj(form.get("cnpj", ""))
    state_registration = form.get("state_registration", "").strip()
    municipal_registration = form.get("municipal_registration", "").strip()
    tax_regime = form.get("tax_regime", "").strip()
    postal_code = re.sub(r"\D", "", form.get("postal_code", ""))
    street = form.get("street", "").strip()
    street_number = form.get("street_number", "").strip()
    district = form.get("district", "").strip()
    city = form.get("city", "").strip()
    state = form.get("state", "").strip().upper()

    if (
        len(legal_name) < 2 or cnpj is None or tax_regime not in TAX_REGIMES
        or not re.fullmatch(r"\d{8}", postal_code)
        or not street or not street_number or not district or not city
        or not re.fullmatch(r"[A-Z]{2}", state)
    ):
        return _render_fiscal(
            "Informe razão social, CNPJ válido, endereço completo, UF e regime tributário.",
            400,
        )

    db = get_db()
    try:
        db.execute(
            """
            INSERT INTO fiscal_issuers
                (legal_name, cnpj, state_registration, municipal_registration,
                 tax_regime, postal_code, street, street_number, district, city, state)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                legal_name, format_cnpj(cnpj), state_registration or None,
                municipal_registration or None, tax_regime, postal_code, street,
                street_number, district, city, state,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return _render_fiscal("Já existe um emitente cadastrado com esse CNPJ.", 409)
    return redirect(url_for("fiscal_page"))


@login_required
def create_fiscal_draft():
    user = get_current_user()
    if not _can_manage_fiscal(user):
        return render_template("forbidden.html", user=user), 403

    request_id = request.form.get("request_id", type=int)
    issuer_id = request.form.get("issuer_id", type=int)
    document_type = request.form.get("document_type", "").strip().lower()
    if not request_id or not issuer_id or document_type not in {"nfe", "nfse"}:
        return _render_fiscal("Selecione uma solicitação, emitente e tipo de documento.", 400)

    db = get_db()
    approved_request = db.execute(
        """
        SELECT r.id, r.title, r.client_name, c.name AS company_name, c.cnpj,
               b.id AS budget_id, b.final_total,
               f.id AS issuer_id, f.legal_name AS issuer_name, f.cnpj AS issuer_cnpj
        FROM requests r
        JOIN companies c ON c.id = r.company_id
        JOIN budgets b ON b.id = (
            SELECT id FROM budgets WHERE request_id = r.id ORDER BY id DESC LIMIT 1
        )
        JOIN fiscal_issuers f ON f.id = ?
        WHERE r.id = ? AND r.status = 'aprovado' AND c.cnpj IS NOT NULL
        """,
        (issuer_id, request_id),
    ).fetchone()
    if approved_request is None:
        return _render_fiscal(
            "Só é possível preparar um rascunho para solicitação aprovada, com orçamento e CNPJ do cliente.",
            400,
        )

    try:
        db.execute(
            """
            INSERT INTO fiscal_drafts
                (request_id, budget_id, issuer_id, document_type, issuer_name,
                 issuer_cnpj, recipient_name, recipient_cnpj, total, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approved_request["id"], approved_request["budget_id"],
                approved_request["issuer_id"], document_type,
                approved_request["issuer_name"], approved_request["issuer_cnpj"],
                approved_request["company_name"], approved_request["cnpj"],
                approved_request["final_total"], user["username"],
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return _render_fiscal(
            "Já existe um rascunho interno desse tipo para esta solicitação.",
            409,
        )

    log_audit(
        request_id,
        "rascunho_fiscal_interno_criado",
        f"Rascunho interno de {document_type.upper()} criado; não transmitido e sem validade fiscal.",
        session.get("full_name", "Sistema"),
    )
    return redirect(url_for("fiscal_page"))


def register_routes(app):
    app.add_url_rule("/fiscal", view_func=fiscal_page, endpoint="fiscal_page")
    app.add_url_rule(
        "/fiscal/emitentes",
        view_func=create_fiscal_issuer,
        endpoint="create_fiscal_issuer",
        methods=["POST"],
    )
    app.add_url_rule(
        "/fiscal/rascunhos",
        view_func=create_fiscal_draft,
        endpoint="create_fiscal_draft",
        methods=["POST"],
    )
