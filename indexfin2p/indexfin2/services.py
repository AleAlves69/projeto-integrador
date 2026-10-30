from flask import render_template, session

from .database import get_db
from .identity import mask_cpf, reveal_cpf
from .security import AVAILABLE_ROLES, MFA_ROLES, get_current_user, normalize_role

def get_request_by_id(request_id):
    db = get_db()
    request_row = db.execute(
        """
        SELECT r.*, c.name AS company_name
        FROM requests r
        LEFT JOIN companies c ON c.id = r.company_id
        WHERE r.id = ?
        """,
        (request_id,),
    ).fetchone()
    return request_row

def can_access_request(user, request_row):
    if user is None:
        return False
    if normalize_role(user["role"]) == "cliente":
        return user["company_id"] is not None and user["company_id"] == request_row["company_id"]
    return True

def log_user_audit(action, details, target_user_id=None, company_id=None):
    db = get_db()
    db.execute(
        """
        INSERT INTO user_audit_logs (actor_id, target_user_id, company_id, action, details)
        VALUES (?, ?, ?, ?, ?)
        """,
        (session.get("user_id", session.get("preauth_user_id")), target_user_id, company_id, action, details),
    )
    db.commit()

def render_user_management(error=None, status=200):
    db = get_db()
    users = db.execute(
        """
        SELECT u.id, u.username, u.full_name, u.role, u.email,
               u.cpf_ciphertext, u.company_id,
               u.active, u.totp_enabled, u.created_at, c.name AS company_name
        FROM users u
        LEFT JOIN companies c ON c.id = u.company_id
        ORDER BY u.full_name COLLATE NOCASE, u.id
        """
    ).fetchall()
    users = [
        {
            **dict(user),
            "cpf_masked": mask_cpf(reveal_cpf(user["cpf_ciphertext"]))
            if user["cpf_ciphertext"] else None,
        }
        for user in users
    ]
    companies = db.execute("SELECT id, name, cnpj FROM companies ORDER BY name").fetchall()
    suppliers = db.execute("SELECT id, name, cnpj, category FROM suppliers ORDER BY name").fetchall()
    recent_changes = db.execute(
        """
        SELECT l.*, actor.username AS actor_username,
               target.username AS target_username, c.name AS company_name
        FROM user_audit_logs l
        LEFT JOIN users actor ON actor.id = l.actor_id
        LEFT JOIN users target ON target.id = l.target_user_id
        LEFT JOIN companies c ON c.id = l.company_id
        ORDER BY l.id DESC
        LIMIT 20
        """
    ).fetchall()
    access_requests = db.execute(
        "SELECT * FROM access_requests WHERE status = 'pendente' ORDER BY created_at, id"
    ).fetchall()
    password_reset_requests = db.execute(
        """
        SELECT p.*, u.full_name, u.email AS account_email
        FROM password_reset_requests p
        LEFT JOIN users u ON lower(u.username) = lower(p.username)
        WHERE p.status = 'pendente'
        ORDER BY p.created_at, p.id
        """
    ).fetchall()
    return render_template(
        "usuarios.html",
        current_user=get_current_user(),
        users=users,
        companies=companies,
        suppliers=suppliers,
        roles=AVAILABLE_ROLES,
        recent_changes=recent_changes,
        access_requests=access_requests,
        password_reset_requests=password_reset_requests,
        mfa_roles=MFA_ROLES,
        error=error,
    ), status

def valid_company_id(company_id):
    if company_id is None:
        return False
    return get_db().execute("SELECT 1 FROM companies WHERE id = ?", (company_id,)).fetchone() is not None

def is_last_active_admin(user, new_role=None, new_active=None):
    remains_admin = user["role"] == "admin" if new_role is None else new_role == "admin"
    remains_active = bool(user["active"]) if new_active is None else bool(new_active)
    if user["role"] != "admin" or not user["active"] or (remains_admin and remains_active):
        return False
    active_admins = get_db().execute(
        "SELECT COUNT(*) AS total FROM users WHERE role = 'admin' AND active = 1"
    ).fetchone()["total"]
    return active_admins <= 1

def get_request_items(request_id):
    db = get_db()
    return db.execute(
        "SELECT * FROM request_items WHERE request_id = ? ORDER BY id",
        (request_id,),
    ).fetchall()

def get_quotes_for_request(request_id):
    db = get_db()
    quotes = db.execute(
        """
        SELECT q.*, s.name AS supplier_name
        FROM quotes q
        JOIN suppliers s ON s.id = q.supplier_id
        WHERE q.request_id = ?
        ORDER BY q.total ASC
        """,
        (request_id,),
    ).fetchall()

    enriched_quotes = []
    for quote in quotes:
        items = db.execute(
            "SELECT * FROM quote_items WHERE quote_id = ? ORDER BY id",
            (quote["id"],),
        ).fetchall()
        enriched_quotes.append({"quote": quote, "items": items})

    return enriched_quotes

def get_budget_for_request(request_id):
    db = get_db()
    budget = db.execute(
        """
        SELECT b.*, q.total AS quote_total, s.name AS supplier_name
        FROM budgets b
        LEFT JOIN quotes q ON q.id = b.quote_id
        LEFT JOIN suppliers s ON s.id = q.supplier_id
        WHERE b.request_id = ?
        ORDER BY b.id DESC
        LIMIT 1
        """,
        (request_id,),
    ).fetchone()
    return budget

def get_approval_requirement(request_row, budget):
    if request_row is None or budget is None:
        return None

    final_total = float(budget["final_total"] or 0)
    initial_budget = float(request_row["initial_budget"] or 0)
    if final_total > initial_budget:
        return {
            "required_role": "admin",
            "stage": "aguardando_aprovacao_admin",
            "label": "Aguardando aprovação do administrador",
        }

    return {
        "required_role": "cliente",
        "stage": "aguardando_aprovacao_cliente",
        "label": "Aguardando aprovação do cliente",
    }

def get_quote_comparison(request_id):
    db = get_db()
    quotes = db.execute(
        """
        SELECT q.*, s.name AS supplier_name
        FROM quotes q
        JOIN suppliers s ON s.id = q.supplier_id
        WHERE q.request_id = ?
        ORDER BY q.total ASC, q.lead_time_days ASC, q.id ASC
        """,
        (request_id,),
    ).fetchall()

    if not quotes:
        return {
            "best_quote": None,
            "quotes": [],
            "initial_budget": 0,
            "budget_alert": False,
        }

    best_quote = quotes[0]
    request_row = get_request_by_id(request_id)
    initial_budget = float(request_row["initial_budget"]) if request_row and request_row["initial_budget"] is not None else 0
    best_total = float(best_quote["total"]) if best_quote["total"] is not None else 0

    return {
        "best_quote": best_quote,
        "quotes": quotes,
        "initial_budget": initial_budget,
        "budget_alert": best_total > initial_budget,
    }

def log_audit(request_id, action, details, created_by):
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_logs (request_id, action, details, created_by)
        VALUES (?, ?, ?, ?)
        """,
        (request_id, action, details, created_by),
    )
    db.commit()

def set_request_status(request_id, new_status, actor_name=None, action="status_alterado"):
    db = get_db()
    db.execute(
        "UPDATE requests SET status = ? WHERE id = ?",
        (new_status, request_id),
    )
    if actor_name is not None:
        log_audit(request_id, action, f"Status alterado para '{new_status}' por {actor_name}.", actor_name)
    db.commit()
