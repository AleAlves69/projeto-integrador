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
def dashboard():
    db = get_db()
    current_user = get_current_user()
    company_filter = ""
    company_params = ()
    if normalize_role(current_user["role"]) == "cliente":
        company_filter = " WHERE company_id = ?"
        company_params = (current_user["company_id"],)
    total_requests = db.execute(
        f"SELECT COUNT(*) AS total FROM requests{company_filter}", company_params
    ).fetchone()["total"]
    total_quotes = db.execute(
        """
        SELECT COUNT(*) AS total FROM quotes q
        JOIN requests r ON r.id = q.request_id
        """ + ("WHERE r.company_id = ?" if company_filter else ""),
        company_params,
    ).fetchone()["total"]
    total_suppliers = db.execute("SELECT COUNT(*) AS total FROM suppliers").fetchone()["total"]
    total_budgets = db.execute(
        """
        SELECT COUNT(*) AS total FROM budgets b
        JOIN requests r ON r.id = b.request_id
        """ + ("WHERE r.company_id = ?" if company_filter else ""),
        company_params,
    ).fetchone()["total"]

    recent_requests = db.execute(
        f"""
        SELECT r.*, c.name AS company_name
        FROM requests r
        LEFT JOIN companies c ON c.id = r.company_id
        {company_filter}
        ORDER BY r.id DESC
        LIMIT 5
        """,
        company_params,
    ).fetchall()

    return render_template(
        "dashboard.html",
        current_user=current_user,
        total_requests=total_requests,
        total_quotes=total_quotes,
        total_suppliers=total_suppliers,
        total_budgets=total_budgets,
        recent_requests=recent_requests,
    )


def register_routes(app):
    app.add_url_rule('/', view_func=dashboard, endpoint='dashboard')
