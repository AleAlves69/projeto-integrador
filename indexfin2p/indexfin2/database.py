import os
import sqlite3
from pathlib import Path

from flask import current_app, g
from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("DATABASE_PATH", BASE_DIR / "indexfin2.db")).resolve()
SCHEMA_PATH = BASE_DIR / "schema.sql"


def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        path_provider = current_app.config.get("DB_PATH_PROVIDER", lambda: DB_PATH)
        db = g._database = sqlite3.connect(path_provider())
        db.row_factory = sqlite3.Row
    return db


def close_db(_exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


def init_db(
    db_path=DB_PATH,
    schema_path=SCHEMA_PATH,
    production=False,
    bootstrap_admin_email=None,
    bootstrap_admin_password=None,
):
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    with schema_path.open("r", encoding="utf-8") as schema_file:
        db.executescript(schema_file.read())
    for index in db.execute("PRAGMA index_list(access_requests)").fetchall():
        if index["unique"]:
            columns = [
                row["name"]
                for row in db.execute(f"PRAGMA index_info('{index['name']}')").fetchall()
            ]
            if columns == ["username"]:
                db.executescript(
                    """
                    ALTER TABLE access_requests RENAME TO access_requests_legacy;
                    CREATE TABLE access_requests (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password_hash TEXT NOT NULL,
                        full_name TEXT NOT NULL,
                        role TEXT NOT NULL,
                        email TEXT NOT NULL,
                        company_name TEXT,
                        status TEXT NOT NULL DEFAULT 'pendente',
                        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        reviewed_at TEXT,
                        reviewed_by INTEGER,
                        FOREIGN KEY (reviewed_by) REFERENCES users(id)
                    );
                    INSERT INTO access_requests
                    SELECT * FROM access_requests_legacy;
                    DROP TABLE access_requests_legacy;
                    """
                )
                break
    user_columns = {row["name"] for row in db.execute("PRAGMA table_info(users)")}
    for column, definition in (
        ("google_sub", "TEXT"),
        ("microsoft_sub", "TEXT"),
        ("totp_secret", "TEXT"),
        ("totp_pending_secret", "TEXT"),
        ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
    ):
        if column not in user_columns:
            db.execute(f"ALTER TABLE users ADD COLUMN {column} {definition}")
    migrations = {
        "users": (("cpf_ciphertext", "TEXT"), ("cpf_lookup", "TEXT")),
        "companies": (("cnpj", "TEXT"),),
        "suppliers": (("cnpj", "TEXT"),),
        "access_requests": (
            ("cpf_ciphertext", "TEXT"),
            ("cpf_lookup", "TEXT"),
            ("company_cnpj", "TEXT"),
        ),
    }
    for table, columns in migrations.items():
        existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
        for column, definition in columns:
            if column not in existing:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    db.executescript(
        """
        CREATE UNIQUE INDEX IF NOT EXISTS idx_users_cpf_lookup
            ON users(cpf_lookup) WHERE cpf_lookup IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_companies_cnpj
            ON companies(cnpj) WHERE cnpj IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_suppliers_cnpj
            ON suppliers(cnpj) WHERE cnpj IS NOT NULL;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_access_requests_cpf_pending
            ON access_requests(cpf_lookup)
            WHERE cpf_lookup IS NOT NULL AND status = 'pendente';
        """
    )
    db.commit()
    db.close()
    seed_data(
        db_path,
        production=production,
        bootstrap_admin_email=bootstrap_admin_email,
        bootstrap_admin_password=bootstrap_admin_password,
    )


def seed_data(
    db_path=DB_PATH,
    production=False,
    bootstrap_admin_email=None,
    bootstrap_admin_password=None,
):
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row

    if production:
        user_count = db.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
        if user_count == 0:
            if not bootstrap_admin_email or not bootstrap_admin_password or len(bootstrap_admin_password) < 16:
                db.close()
                raise RuntimeError(
                    "For a new production database, configure BOOTSTRAP_ADMIN_EMAIL "
                    "and a BOOTSTRAP_ADMIN_PASSWORD with at least 16 characters."
                )
            db.execute(
                """
                INSERT INTO users (username, password_hash, full_name, role, email)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    "admin",
                    generate_password_hash(bootstrap_admin_password),
                    "Administrador do sistema",
                    "admin",
                    bootstrap_admin_email.strip().lower(),
                ),
            )
        db.commit()
        db.close()
        return

    company_count = db.execute("SELECT COUNT(*) AS total FROM companies").fetchone()["total"]
    if company_count == 0:
        db.executemany(
            "INSERT INTO companies (name) VALUES (?)",
            [
                ("Alpha Industrial",),
                ("Nexa Saúde",),
                ("BlueStone Logística",),
            ],
        )

    supplier_count = db.execute("SELECT COUNT(*) AS total FROM suppliers").fetchone()["total"]
    if supplier_count == 0:
        db.executemany(
            "INSERT INTO suppliers (name, category, lead_time_days, payment_terms) VALUES (?, ?, ?, ?)",
            [
                ("Comercial Norte", "Material de escritório", 7, "30/60 dias"),
                ("Tecno Supply", "Tecnologia", 5, "À vista"),
                ("Prime Logistics", "Logística", 10, "30 dias"),
            ],
        )

    user_count = db.execute("SELECT COUNT(*) AS total FROM users").fetchone()["total"]
    if user_count == 0:
        db.executemany(
            """
            INSERT INTO users (username, password_hash, full_name, role, email)
            VALUES (?, ?, ?, ?, ?)
            """,
            [
                ("admin", generate_password_hash("admin123"), "Administrador do sistema", "admin", "admin@indexfin2.local"),
                ("operador", generate_password_hash("operador123"), "Operador de compras", "operador", "operador@indexfin2.local"),
                ("operador_comercial", generate_password_hash("opcom123"), "Operador comercial", "operador_comercial", "operador_comercial@indexfin2.local"),
                ("operador_financeiro", generate_password_hash("opfin123"), "Operador financeiro", "operador_financeiro", "operador_financeiro@indexfin2.local"),
                ("cliente", generate_password_hash("cliente123"), "Cliente principal", "cliente", "cliente@indexfin2.local"),
                ("fornecedor", generate_password_hash("fornecedor123"), "Fornecedor principal", "fornecedor", "fornecedor@indexfin2.local"),
                ("auditor", generate_password_hash("auditor123"), "Auditor interno", "auditor", "auditor@indexfin2.local"),
            ],
        )

    default_company = db.execute(
        "SELECT id FROM companies WHERE name = 'Alpha Industrial' ORDER BY id LIMIT 1"
    ).fetchone()
    if default_company:
        db.execute(
            "UPDATE users SET company_id = ? WHERE username = 'cliente' AND company_id IS NULL",
            (default_company["id"],),
        )

    request_count = db.execute("SELECT COUNT(*) AS total FROM requests").fetchone()["total"]
    if request_count == 0:
        company_id = db.execute("SELECT id FROM companies WHERE name = 'Alpha Industrial'").fetchone()["id"]
        supplier_1 = db.execute("SELECT id FROM suppliers WHERE name = 'Comercial Norte'").fetchone()["id"]
        supplier_2 = db.execute("SELECT id FROM suppliers WHERE name = 'Tecno Supply'").fetchone()["id"]

        request_id = db.execute(
            """
            INSERT INTO requests (title, client_name, company_id, initial_budget, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("Solicitação de material de escritório", "Maria C. Silva", company_id, 8500.00, "em cotação", "Operador comercial"),
        ).lastrowid

        db.executemany(
            "INSERT INTO request_items (request_id, description, quantity, unit, estimated_unit_price) VALUES (?, ?, ?, ?, ?)",
            [
                (request_id, "Computador portátil para equipe de vendas", 6, "un", 5200.00),
                (request_id, "Cadeira ergonômica", 12, "un", 950.00),
            ],
        )

        quote_1_id = db.execute(
            """
            INSERT INTO quotes (request_id, supplier_id, total, lead_time_days, payment_terms, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (request_id, supplier_1, 56200.00, 8, "30/60 dias", "Inclui assistência e garantia estendida."),
        ).lastrowid

        db.executemany(
            "INSERT INTO quote_items (quote_id, description, quantity, unit, unit_price) VALUES (?, ?, ?, ?, ?)",
            [
                (quote_1_id, "Computador portátil para equipe de vendas", 6, "un", 5300.00),
                (quote_1_id, "Cadeira ergonômica", 12, "un", 980.00),
            ],
        )

        quote_2_id = db.execute(
            """
            INSERT INTO quotes (request_id, supplier_id, total, lead_time_days, payment_terms, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (request_id, supplier_2, 54880.00, 5, "À vista", "Entrega mais rápida e melhor garantia de peças."),
        ).lastrowid

        db.executemany(
            "INSERT INTO quote_items (quote_id, description, quantity, unit, unit_price) VALUES (?, ?, ?, ?, ?)",
            [
                (quote_2_id, "Computador portátil para equipe de vendas", 6, "un", 5150.00),
                (quote_2_id, "Cadeira ergonômica", 12, "un", 920.00),
            ],
        )

        db.execute(
            """
            INSERT INTO budgets (request_id, quote_id, final_total, validity_days, status, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (request_id, quote_2_id, 54880.00, 15, "enviado", "Orçamento final proposto para aprovação do cliente."),
        )

        request_two_id = db.execute(
            """
            INSERT INTO requests (title, client_name, company_id, initial_budget, status, created_by)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            ("Cotação de transporte e logística", "Paulo R. Martins", company_id, 4200.00, "aprovado", "Supervisor operacional"),
        ).lastrowid

        db.executemany(
            "INSERT INTO request_items (request_id, description, quantity, unit, estimated_unit_price) VALUES (?, ?, ?, ?, ?)",
            [
                (request_two_id, "Frete de entrega regional", 2, "viagem", 1700.00),
                (request_two_id, "Seguro da carga", 1, "serviço", 650.00),
            ],
        )

        supplier_log = db.execute("SELECT id FROM suppliers WHERE name = 'Prime Logistics'").fetchone()["id"]
        quote_three_id = db.execute(
            """
            INSERT INTO quotes (request_id, supplier_id, total, lead_time_days, payment_terms, notes)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (request_two_id, supplier_log, 3950.00, 10, "30 dias", "Frete com rastreio e garantia de entrega.")
        ).lastrowid

        db.executemany(
            "INSERT INTO quote_items (quote_id, description, quantity, unit, unit_price) VALUES (?, ?, ?, ?, ?)",
            [
                (quote_three_id, "Frete de entrega regional", 2, "viagem", 1600.00),
                (quote_three_id, "Seguro da carga", 1, "serviço", 750.00),
            ],
        )

    db.commit()
    db.close()
