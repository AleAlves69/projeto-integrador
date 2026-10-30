import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import app as app_module
import pyotp
from cryptography.fernet import Fernet
from indexfin2.identity import (
    format_cnpj, normalize_cnpj, normalize_cpf, protect_cpf, reveal_cpf,
)
from werkzeug.security import check_password_hash


def test_cnpj(base):
    weights = (5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    total = sum((ord(char) - 48) * weight for char, weight in zip(base, weights))
    first = 0 if total % 11 < 2 else 11 - total % 11
    body = f"{base}{first}"
    weights = (6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2)
    total = sum((ord(char) - 48) * weight for char, weight in zip(body, weights))
    second = 0 if total % 11 < 2 else 11 - total % 11
    return f"{body}{second}"


def test_cpf(seed):
    digits = f"{seed % 1_000_000_000:09d}"
    for length, factor in ((9, 10), (10, 11)):
        total = sum(int(digits[index]) * (factor - index) for index in range(length))
        digit = (total * 10) % 11
        digits += str(0 if digit == 10 else digit)
    return digits


class IndexFin2BusinessRulesTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_indexfin2.db"
        app_module.DB_PATH = self.db_path
        app_module.app.config["TESTING"] = True
        app_module.app.config["CPF_ENCRYPTION_KEY"] = Fernet.generate_key().decode("ascii")
        app_module.init_db()
        with app_module.app.app_context(), sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            users = db.execute("SELECT id, username FROM users ORDER BY id").fetchall()
            for user in users:
                seed = sum((index + 1) * ord(char) for index, char in enumerate(user["username"]))
                encrypted, lookup = protect_cpf(test_cpf(seed))
                db.execute(
                    "UPDATE users SET cpf_ciphertext = ?, cpf_lookup = ? WHERE id = ?",
                    (encrypted, lookup, user["id"]),
                )
            suppliers = db.execute("SELECT id, name FROM suppliers ORDER BY id").fetchall()
            for supplier in suppliers:
                seed = sum((index + 1) * ord(char) for index, char in enumerate(supplier["name"]))
                db.execute(
                    "UPDATE suppliers SET cnpj = ? WHERE id = ?",
                    (format_cnpj(test_cnpj(f"{seed:012d}"[-12:])), supplier["id"]),
                )
            db.commit()
        self.client = app_module.app.test_client()

    def tearDown(self):
        try:
            if self.db_path.exists():
                self.db_path.unlink()
        except OSError:
            pass
        finally:
            shutil.rmtree(self.temp_dir.name, ignore_errors=True)

    def login(self, username, password):
        response = self.client.post(
            "/login",
            data={"username": username, "password": password},
            follow_redirects=False,
        )
        if response.status_code != 302:
            return response
        location = response.headers.get("Location", "")
        if location.endswith("/2fa/configurar"):
            self.client.get(location)
            with sqlite3.connect(self.db_path) as db:
                secret = db.execute(
                    "SELECT totp_pending_secret FROM users WHERE username = ?", (username,)
                ).fetchone()[0]
            return self.client.post(
                location,
                data={"code": pyotp.TOTP(secret).now()},
                follow_redirects=False,
            )
        if location.endswith("/2fa/verificar"):
            with sqlite3.connect(self.db_path) as db:
                secret = db.execute(
                    "SELECT totp_secret FROM users WHERE username = ?", (username,)
                ).fetchone()[0]
            return self.client.post(
                location,
                data={"code": pyotp.TOTP(secret).now()},
                follow_redirects=False,
            )
        return response

    def create_request(self, title="Solicitação de teste", client_name="Cliente teste", company_id=1, initial_budget=5000):
        response = self.client.post(
            "/solicitacoes/nova",
            data={
                "title": title,
                "client_name": client_name,
                "company_id": company_id,
                "initial_budget": initial_budget,
                "status": "em cotação",
                "item_1_description": "Notebook",
                "item_1_quantity": "1",
                "item_1_unit": "un",
                "item_1_unit_price": "1500",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        location = response.headers.get("Location", "")
        request_id = int(location.rsplit("/", 1)[-1])
        return request_id

    def add_quote(self, request_id, supplier_id, total):
        response = self.client.post(
            f"/solicitacoes/{request_id}/cotacao",
            data={
                "supplier_id": supplier_id,
                "total": total,
                "lead_time_days": 7,
                "payment_terms": "30 dias",
                "notes": "Cotação de teste",
                "item_1_description": "Notebook",
                "item_1_quantity": "1",
                "item_1_unit": "un",
                "item_1_unit_price": total,
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

    def test_document_validation_and_encryption(self):
        self.assertEqual(normalize_cpf("529.982.247-25"), "52998224725")
        self.assertIsNone(normalize_cpf("111.111.111-11"))
        self.assertEqual(normalize_cnpj("04.252.011/0001-10"), "04252011000110")
        alpha_cnpj = test_cnpj("12ABC34501DE")
        self.assertEqual(normalize_cnpj(alpha_cnpj), alpha_cnpj)
        with app_module.app.app_context():
            encrypted, lookup = protect_cpf("52998224725")
            revealed = reveal_cpf(encrypted)
        self.assertNotIn("52998224725", encrypted)
        self.assertEqual(revealed, "52998224725")
        self.assertEqual(len(lookup), 64)

    def test_database_migration_preserves_existing_accounts_and_businesses(self):
        legacy_path = Path(self.temp_dir.name) / "legacy_indexfin2.db"
        with sqlite3.connect(legacy_path) as db:
            db.executescript(
                """
                CREATE TABLE companies (id INTEGER PRIMARY KEY, name TEXT NOT NULL);
                CREATE TABLE suppliers (
                    id INTEGER PRIMARY KEY, name TEXT NOT NULL, category TEXT,
                    lead_time_days INTEGER, payment_terms TEXT
                );
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL, full_name TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'operador', email TEXT, company_id INTEGER,
                    active INTEGER NOT NULL DEFAULT 1, google_sub TEXT UNIQUE,
                    microsoft_sub TEXT UNIQUE, totp_secret TEXT, totp_pending_secret TEXT,
                    totp_enabled INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE access_requests (
                    id INTEGER PRIMARY KEY, username TEXT NOT NULL,
                    password_hash TEXT NOT NULL, full_name TEXT NOT NULL,
                    role TEXT NOT NULL, email TEXT NOT NULL, company_name TEXT,
                    status TEXT NOT NULL DEFAULT 'pendente',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    reviewed_at TEXT, reviewed_by INTEGER
                );
                INSERT INTO companies (id, name) VALUES (1, 'Empresa existente');
                INSERT INTO suppliers (id, name) VALUES (1, 'Fornecedor existente');
                INSERT INTO users (id, username, password_hash, full_name, role, email)
                    VALUES (1, 'admin', 'hash', 'Admin existente', 'admin', 'admin@example.test');
                INSERT INTO access_requests
                    (id, username, password_hash, full_name, role, email)
                    VALUES (1, 'pendente', 'hash', 'Conta pendente', 'cliente', 'pending@example.test');
                """
            )

        app_module.database.init_db(
            legacy_path,
            app_module.SCHEMA_PATH,
            production=True,
        )
        with sqlite3.connect(legacy_path) as db:
            self.assertEqual(
                db.execute("SELECT name FROM companies WHERE id = 1").fetchone()[0],
                "Empresa existente",
            )
            self.assertEqual(
                db.execute("SELECT username FROM users WHERE id = 1").fetchone()[0],
                "admin",
            )
            self.assertEqual(
                db.execute("SELECT name FROM suppliers WHERE id = 1").fetchone()[0],
                "Fornecedor existente",
            )
            self.assertIn(
                "cpf_ciphertext",
                {row[1] for row in db.execute("PRAGMA table_info(users)")},
            )
            self.assertIn("cnpj", {row[1] for row in db.execute("PRAGMA table_info(companies)")})
            self.assertIn("cnpj", {row[1] for row in db.execute("PRAGMA table_info(suppliers)")})
            table_names = {
                row[0] for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
            self.assertIn("fiscal_issuers", table_names)
            self.assertIn("fiscal_drafts", table_names)
            self.assertIsNone(
                db.execute("SELECT cpf_ciphertext FROM access_requests WHERE id = 1").fetchone()[0]
            )

    def test_existing_user_must_complete_cpf_before_access(self):
        with sqlite3.connect(self.db_path) as db:
            db.execute(
                "UPDATE users SET cpf_ciphertext = NULL, cpf_lookup = NULL WHERE username = 'admin'"
            )

        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/cadastro/completar-cpf", response.headers["Location"])
        self.assertEqual(self.client.get("/").headers["Location"], "/cadastro/completar-cpf?next=/")

        cpf = test_cpf(987654321)
        response = self.client.post(
            "/cadastro/completar-cpf?next=/",
            data={"cpf": cpf},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/")
        with sqlite3.connect(self.db_path) as db:
            ciphertext, lookup = db.execute(
                "SELECT cpf_ciphertext, cpf_lookup FROM users WHERE username = 'admin'"
            ).fetchone()
        self.assertNotIn(cpf, ciphertext)
        self.assertEqual(self.client.get("/").status_code, 200)

    def create_budget(self, request_id, quote_id, final_total, status="enviado"):
        response = self.client.post(
            f"/solicitacoes/{request_id}/orcamento",
            data={
                "quote_id": quote_id,
                "final_total": final_total,
                "validity_days": 15,
                "status": status,
                "notes": "Orçamento em teste",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

    def test_login_and_dashboard_are_protected(self):
        response = self.login("admin", "admin123")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers.get("Location"), "/")

        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("Painel de gestão", dashboard.get_data(as_text=True))

        self.client.get("/logout")
        response = self.login("cliente", "cliente123")
        self.assertEqual(response.status_code, 302)

        response = self.client.get("/solicitacoes/nova")
        self.assertEqual(response.status_code, 403)

    def test_client_cannot_approve_budget_over_initial_value(self):
        self.login("admin", "admin123")
        request_id = self.create_request(initial_budget=5000)
        self.add_quote(request_id, 1, 5200)
        self.create_budget(request_id, 1, 5200)

        self.client.get("/logout")
        self.login("cliente", "cliente123")

        response = self.client.post(
            f"/solicitacoes/{request_id}/aprovacao",
            data={"action": "aprovar"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 403)

        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            status = db.execute("SELECT status FROM requests WHERE id = ?", (request_id,)).fetchone()["status"]
        self.assertEqual(status, "aguardando_aprovacao_admin")

    def test_admin_approves_when_budget_exceeds_limit(self):
        self.login("admin", "admin123")
        request_id = self.create_request(initial_budget=5000)
        self.add_quote(request_id, 1, 6800)
        self.create_budget(request_id, 1, 6800)

        self.client.get("/logout")
        self.login("admin", "admin123")

        response = self.client.post(
            f"/solicitacoes/{request_id}/aprovacao",
            data={"action": "aprovar"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            status = db.execute("SELECT status FROM requests WHERE id = ?", (request_id,)).fetchone()["status"]
        self.assertEqual(status, "aprovado")

    def test_operador_comercial_has_access_to_create_request(self):
        response = self.login("operador_comercial", "opcom123")
        self.assertEqual(response.status_code, 302)

        response = self.client.get("/solicitacoes/nova")
        self.assertEqual(response.status_code, 200)

    def test_best_quote_and_budget_alert_are_displayed(self):
        self.login("admin", "admin123")
        request_id = self.create_request(initial_budget=5000)
        self.add_quote(request_id, 1, 5200)
        self.add_quote(request_id, 2, 4700)

        response = self.client.get(f"/solicitacoes/{request_id}")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Comparação automática de cotações", html)
        self.assertIn("Melhor proposta", html)

    def test_approval_stage_is_visible_and_enforced_by_role(self):
        self.login("admin", "admin123")
        request_id = self.create_request(initial_budget=5000)
        self.add_quote(request_id, 1, 4700)
        self.create_budget(request_id, 1, 4700)

        self.client.get("/logout")
        self.login("cliente", "cliente123")

        response = self.client.get(f"/solicitacoes/{request_id}")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Aguardando aprovação do cliente", html)

        response = self.client.post(
            f"/solicitacoes/{request_id}/aprovacao",
            data={"action": "aprovar"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        self.client.get("/logout")
        self.login("admin", "admin123")
        request_id_2 = self.create_request(title="Nova etapa de aprovação", initial_budget=2500)
        self.add_quote(request_id_2, 1, 3100)
        self.create_budget(request_id_2, 1, 3100)

        response = self.client.get(f"/solicitacoes/{request_id_2}")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Aguardando aprovação do administrador", html)

    def test_admin_manages_company_users_and_passwords(self):
        self.login("admin", "admin123")
        panel = self.client.get("/usuarios")
        self.assertEqual(panel.status_code, 200)
        self.assertIn("operador_comercial", panel.get_data(as_text=True))
        self.assertNotIn("password_hash", panel.get_data(as_text=True))

        with sqlite3.connect(self.db_path) as db:
            existing_company_id = db.execute(
                "SELECT id FROM companies WHERE name = 'Alpha Industrial'"
            ).fetchone()[0]
        self.assertEqual(
            self.client.post(
                f"/empresas/{existing_company_id}",
                data={"cnpj": "04.252.011/0001-10"},
            ).status_code,
            302,
        )
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(
                db.execute(
                    "SELECT cnpj FROM companies WHERE id = ?", (existing_company_id,)
                ).fetchone()[0],
                "04.252.011/0001-10",
            )

        self.assertEqual(
            self.client.post(
                "/empresas",
                data={"name": "Empresa de Teste", "cnpj": "11.222.333/0001-81"},
            ).status_code,
            302,
        )
        self.assertEqual(
            self.client.post(
                "/fornecedores",
                data={
                    "name": "Fornecedor de Teste",
                    "cnpj": "12.345.678/0001-95",
                    "category": "Tecnologia",
                },
            ).status_code,
            302,
        )
        with sqlite3.connect(self.db_path) as db:
            company_id = db.execute(
                "SELECT id FROM companies WHERE name = ?", ("Empresa de Teste",)
            ).fetchone()[0]

        response = self.client.post(
            "/usuarios",
            data={
                "username": "cliente-nexa",
                "full_name": "Cliente Nexa",
                "email": "nexa@example.test",
                "cpf": test_cpf(123456789),
                "password": "senha-inicial-1",
                "role": "cliente",
                "company_id": str(company_id),
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)

        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            user = db.execute(
                "SELECT id, password_hash, company_id FROM users WHERE username = ?",
                ("cliente-nexa",),
            ).fetchone()
        self.assertEqual(user["company_id"], company_id)
        self.assertNotEqual(user["password_hash"], "senha-inicial-1")
        user_id = user["id"]

        restricted_request_id = self.create_request(title="Solicitação Alpha", company_id=1)
        self.client.get("/logout")
        self.login("cliente-nexa", "senha-inicial-1")
        self.assertNotIn("Solicitação Alpha", self.client.get("/solicitacoes").get_data(as_text=True))
        self.assertEqual(self.client.get(f"/solicitacoes/{restricted_request_id}").status_code, 404)
        self.assertEqual(self.client.get("/usuarios").status_code, 403)

        self.client.get("/logout")
        self.login("admin", "admin123")
        response = self.client.post(
            f"/usuarios/{user_id}/senha",
            data={"password": "nova-senha-123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        self.client.post(
            f"/usuarios/{user_id}/status",
            data={"action": "inativar", "reason": "Conta de teste"},
        )
        self.client.get("/logout")
        inactive_login = self.login("cliente-nexa", "nova-senha-123")
        self.assertEqual(inactive_login.status_code, 200)
        self.assertIn("inativa", inactive_login.get_data(as_text=True))

    def test_admin_cannot_disable_or_demote_last_admin(self):
        self.login("admin", "admin123")
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            admin_id = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()["id"]

        response = self.client.post(
            f"/usuarios/{admin_id}/status",
            data={"action": "inativar", "reason": "Teste"},
        )
        self.assertEqual(response.status_code, 409)

        response = self.client.post(
            f"/usuarios/{admin_id}/editar",
            data={
                "full_name": "Administrador",
                "email": "admin@example.test",
                "role": "operador",
                "company_id": "",
                "role_reason": "Teste de proteção do último administrador",
            },
        )
        self.assertEqual(response.status_code, 409)

    def test_login_offers_first_access_and_password_recovery(self):
        login_page = self.client.get("/login").get_data(as_text=True)
        self.assertIn("Primeiro acesso", login_page)
        self.assertIn("Esqueci minha senha", login_page)

        response = self.client.post(
            "/primeiro-acesso",
            data={
                "full_name": "Operador Novo",
                "username": "operador-novo",
                "email": "novo@example.test",
                "role": "operador_comercial",
                "company_name": "",
                "cpf": test_cpf(234567891),
                "password": "senha-nova-123",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("aprovar o cadastro", response.get_data(as_text=True).lower())
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users WHERE username = 'operador-novo'").fetchone()[0], 0)
            access_request = db.execute(
                "SELECT id, cpf_ciphertext, cpf_lookup FROM access_requests WHERE username = 'operador-novo'"
            ).fetchone()
            access_id = access_request[0]
            self.assertNotIn(test_cpf(234567891), access_request[1])

        self.assertEqual(self.login("operador-novo", "senha-nova-123").status_code, 200)
        self.login("admin", "admin123")
        approval = self.client.post(
            f"/usuarios/acessos/{access_id}",
            data={"action": "aprovar"},
            follow_redirects=False,
        )
        self.assertEqual(approval.status_code, 302)
        with sqlite3.connect(self.db_path) as db:
            created_user_cpf = db.execute(
                "SELECT cpf_ciphertext, cpf_lookup FROM users WHERE username = 'operador-novo'"
            ).fetchone()
        self.assertEqual(created_user_cpf[0], access_request[1])
        self.assertEqual(created_user_cpf[1], access_request[2])
        self.client.get("/logout")
        self.assertEqual(self.login("operador-novo", "senha-nova-123").status_code, 302)

        self.client.get("/logout")
        response = self.client.post(
            "/primeiro-acesso",
            data={
                "full_name": "Cliente Novo",
                "username": "cliente-novo",
                "email": "cliente-novo@example.test",
                "role": "cliente",
                "company_name": "Empresa Nova",
                "company_cnpj": "11.222.333/0001-81",
                "cpf": test_cpf(345678912),
                "password": "senha-cliente-123",
            },
        )
        self.assertEqual(response.status_code, 200)
        with sqlite3.connect(self.db_path) as db:
            customer_access_id = db.execute(
                "SELECT id FROM access_requests WHERE username = 'cliente-novo'"
            ).fetchone()[0]
        self.login("admin", "admin123")
        self.client.post(
            f"/usuarios/acessos/{customer_access_id}",
            data={"action": "aprovar"},
        )
        with sqlite3.connect(self.db_path) as db:
            customer_company = db.execute(
                """
                SELECT c.name FROM users u
                JOIN companies c ON c.id = u.company_id
                WHERE u.username = 'cliente-novo'
                """
            ).fetchone()[0]
        self.assertEqual(customer_company, "Empresa Nova")

    def test_forgot_password_creates_admin_request_and_admin_reset_resolves_it(self):
        response = self.client.post(
            "/esqueci-senha",
            data={"username": "cliente", "email": "cliente@indexfin2.local"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("administrador", response.get_data(as_text=True))
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM password_reset_requests WHERE username = 'cliente' AND status = 'pendente'"
                ).fetchone()[0],
                1,
            )

        self.login("admin", "admin123")
        with sqlite3.connect(self.db_path) as db:
            user_id = db.execute("SELECT id FROM users WHERE username = 'cliente'").fetchone()[0]
        response = self.client.post(
            f"/usuarios/{user_id}/senha",
            data={"password": "senha-recuperada-123"},
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.db_path) as db:
            status = db.execute(
                "SELECT status FROM password_reset_requests WHERE username = 'cliente'"
            ).fetchone()[0]
        self.assertEqual(status, "resolvida")

    def test_admin_login_skips_totp_but_operator_still_requires_it(self):
        response = self.client.post(
            "/login",
            data={"username": "admin", "password": "admin123"},
            follow_redirects=False,
        )
        self.assertEqual(response.headers.get("Location"), "/")
        self.assertEqual(self.client.get("/").status_code, 200)

        self.client.get("/logout")
        response = self.client.post(
            "/login",
            data={"username": "operador", "password": "operador123"},
            follow_redirects=False,
        )
        self.assertEqual(response.headers.get("Location"), "/2fa/configurar")
        self.assertEqual(self.client.get("/").status_code, 302)
        setup_page = self.client.get("/2fa/configurar")
        self.assertEqual(setup_page.status_code, 200)
        with self.client.session_transaction() as current_session:
            self.assertNotIn("totp_setup_secret", current_session)
        with sqlite3.connect(self.db_path) as db:
            secret = db.execute(
                "SELECT totp_pending_secret FROM users WHERE username = 'operador'"
            ).fetchone()[0]
        self.assertEqual(
            self.client.post("/2fa/configurar", data={"code": "000000"}).status_code,
            400,
        )
        response = self.client.post(
            "/2fa/configurar",
            data={"code": pyotp.TOTP(secret).now()},
            follow_redirects=False,
        )
        self.assertEqual(response.headers.get("Location"), "/")
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(
                db.execute("SELECT totp_enabled FROM users WHERE username = 'operador'").fetchone()[0],
                1,
            )

        self.client.get("/logout")
        response = self.client.post(
            "/login",
            data={"username": "operador", "password": "operador123"},
            follow_redirects=False,
        )
        self.assertEqual(response.headers.get("Location"), "/2fa/verificar")
        self.client.get(response.headers["Location"])
        with sqlite3.connect(self.db_path) as db:
            secret = db.execute(
                "SELECT totp_secret FROM users WHERE username = 'operador'"
            ).fetchone()[0]
        verified = self.client.post(
            "/2fa/verificar",
            data={"code": pyotp.TOTP(secret).now()},
            follow_redirects=False,
        )
        self.assertEqual(verified.headers.get("Location"), "/")
        self.assertEqual(self.client.get("/").status_code, 200)

    def test_production_database_bootstraps_only_the_configured_admin(self):
        production_db = Path(self.temp_dir.name) / "production" / "indexfin2.db"
        password = "a-long-unique-production-password"
        app_module.database.init_db(
            production_db,
            app_module.SCHEMA_PATH,
            production=True,
            bootstrap_admin_email="owner@example.com",
            bootstrap_admin_password=password,
        )
        with sqlite3.connect(production_db) as db:
            admin = db.execute(
                "SELECT username, password_hash, email FROM users"
            ).fetchone()
            self.assertEqual(admin[0], "admin")
            self.assertTrue(check_password_hash(admin[1], password))
            self.assertEqual(admin[2], "owner@example.com")
            self.assertEqual(db.execute("SELECT COUNT(*) FROM companies").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM suppliers").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 0)

    def test_production_database_rejects_missing_bootstrap_credentials(self):
        with self.assertRaisesRegex(RuntimeError, "BOOTSTRAP_ADMIN_PASSWORD"):
            app_module.database.init_db(
                Path(self.temp_dir.name) / "production-empty.db",
                app_module.SCHEMA_PATH,
                production=True,
            )

    def test_sso_buttons_are_hidden_until_provider_credentials_exist(self):
        login_page = self.client.get("/login").get_data(as_text=True)
        self.assertNotIn("Entrar com Google", login_page)
        self.assertNotIn("Entrar com Microsoft", login_page)
        self.assertEqual(self.client.get("/login/google").status_code, 302)

    def test_sso_links_only_to_an_existing_approved_user(self):
        oauth_client = Mock()
        oauth_client.authorize_access_token.return_value = {
            "userinfo": {
                "email": "cliente@indexfin2.local",
                "email_verified": True,
                "sub": "google-subject-123",
            }
        }
        with patch.dict(app_module.SSO_PROVIDERS, {"google": "Google"}):
            with patch.object(app_module.oauth, "create_client", return_value=oauth_client):
                response = self.client.get("/login/google/callback", follow_redirects=False)

        self.assertEqual(response.headers.get("Location"), "/")
        with sqlite3.connect(self.db_path) as db:
            subject = db.execute(
                "SELECT google_sub FROM users WHERE username = 'cliente'"
            ).fetchone()[0]
        self.assertEqual(subject, "google-subject-123")

    def test_fiscal_preparation_creates_only_internal_draft_for_approved_request(self):
        self.login("admin", "admin123")
        fiscal_page = self.client.get("/fiscal")
        self.assertEqual(fiscal_page.status_code, 200)
        self.assertIn("não têm validade fiscal", fiscal_page.get_data(as_text=True))

        client_cnpj = format_cnpj(test_cnpj("123456780001"))
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            db.execute("UPDATE companies SET cnpj = ? WHERE id = 1", (client_cnpj,))
            request_id = db.execute(
                """
                INSERT INTO requests
                    (title, client_name, company_id, initial_budget, status, created_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                ("Venda aprovada", "Cliente teste", 1, 1000, "aprovado", "Teste"),
            ).lastrowid
            budget_id = db.execute(
                """
                INSERT INTO budgets (request_id, final_total, status)
                VALUES (?, ?, ?)
                """,
                (request_id, 950.0, "aprovado"),
            ).lastrowid

        issuer_cnpj = format_cnpj(test_cnpj("987654320001"))
        response = self.client.post(
            "/fiscal/emitentes",
            data={
                "legal_name": "Empresa Emissora Teste",
                "cnpj": issuer_cnpj,
                "state_registration": "123456789",
                "municipal_registration": "987654",
                "tax_regime": "simples_nacional",
                "postal_code": "01001000",
                "street": "Rua de Teste",
                "street_number": "10",
                "district": "Centro",
                "city": "São Paulo",
                "state": "sp",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.db_path) as db:
            issuer_id = db.execute(
                "SELECT id FROM fiscal_issuers WHERE cnpj = ?", (issuer_cnpj,)
            ).fetchone()[0]

        response = self.client.post(
            "/fiscal/rascunhos",
            data={
                "request_id": str(request_id),
                "issuer_id": str(issuer_id),
                "document_type": "nfe",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 302)
        with sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            draft = db.execute(
                "SELECT * FROM fiscal_drafts WHERE request_id = ?", (request_id,)
            ).fetchone()
        self.assertEqual(draft["budget_id"], budget_id)
        self.assertEqual(draft["document_type"], "nfe")
        self.assertEqual(draft["status"], "rascunho_interno")
        self.assertEqual(draft["total"], 950.0)
        self.assertEqual(draft["recipient_cnpj"], client_cnpj)
        self.assertNotIn("xml", draft.keys())
        self.assertNotIn("access_key", draft.keys())

        duplicate = self.client.post(
            "/fiscal/rascunhos",
            data={
                "request_id": str(request_id),
                "issuer_id": str(issuer_id),
                "document_type": "nfe",
            },
        )
        self.assertEqual(duplicate.status_code, 409)

        unapproved_id = self.create_request(title="Solicitação ainda pendente")
        blocked = self.client.post(
            "/fiscal/rascunhos",
            data={
                "request_id": str(unapproved_id),
                "issuer_id": str(issuer_id),
                "document_type": "nfse",
            },
        )
        self.assertEqual(blocked.status_code, 400)
        with sqlite3.connect(self.db_path) as db:
            self.assertEqual(
                db.execute(
                    "SELECT COUNT(*) FROM fiscal_drafts WHERE request_id = ?",
                    (unapproved_id,),
                ).fetchone()[0],
                0,
            )

        self.client.get("/logout")
        self.login("cliente", "cliente123")
        self.assertEqual(self.client.get("/fiscal").status_code, 403)


if __name__ == "__main__":
    unittest.main()
