CREATE TABLE IF NOT EXISTS companies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    cnpj TEXT
);

CREATE TABLE IF NOT EXISTS suppliers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    cnpj TEXT,
    category TEXT,
    lead_time_days INTEGER,
    payment_terms TEXT
);

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'operador',
    email TEXT,
    cpf_ciphertext TEXT,
    cpf_lookup TEXT,
    company_id INTEGER,
    active INTEGER NOT NULL DEFAULT 1,
    google_sub TEXT UNIQUE,
    microsoft_sub TEXT UNIQUE,
    totp_secret TEXT,
    totp_pending_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE IF NOT EXISTS requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    client_name TEXT NOT NULL,
    company_id INTEGER,
    initial_budget REAL NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'em cotação',
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE IF NOT EXISTS request_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity REAL NOT NULL,
    unit TEXT,
    estimated_unit_price REAL,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS quotes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    supplier_id INTEGER NOT NULL,
    total REAL NOT NULL,
    lead_time_days INTEGER,
    payment_terms TEXT,
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES requests(id),
    FOREIGN KEY (supplier_id) REFERENCES suppliers(id)
);

CREATE TABLE IF NOT EXISTS quote_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    quote_id INTEGER NOT NULL,
    description TEXT NOT NULL,
    quantity REAL NOT NULL,
    unit TEXT,
    unit_price REAL,
    FOREIGN KEY (quote_id) REFERENCES quotes(id)
);

CREATE TABLE IF NOT EXISTS budgets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    quote_id INTEGER,
    final_total REAL NOT NULL,
    validity_days INTEGER,
    status TEXT NOT NULL DEFAULT 'enviado',
    notes TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (request_id) REFERENCES requests(id),
    FOREIGN KEY (quote_id) REFERENCES quotes(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    created_by TEXT,
    FOREIGN KEY (request_id) REFERENCES requests(id)
);

CREATE TABLE IF NOT EXISTS user_audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id INTEGER,
    target_user_id INTEGER,
    company_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_id) REFERENCES users(id),
    FOREIGN KEY (target_user_id) REFERENCES users(id),
    FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE TABLE IF NOT EXISTS access_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL,
    email TEXT NOT NULL,
    company_name TEXT,
    cpf_ciphertext TEXT,
    cpf_lookup TEXT,
    company_cnpj TEXT,
    status TEXT NOT NULL DEFAULT 'pendente',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewed_by INTEGER,
    FOREIGN KEY (reviewed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_reset_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    email TEXT,
    status TEXT NOT NULL DEFAULT 'pendente',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resolved_at TEXT,
    resolved_by INTEGER,
    FOREIGN KEY (resolved_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS fiscal_issuers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    legal_name TEXT NOT NULL,
    cnpj TEXT NOT NULL UNIQUE,
    state_registration TEXT,
    municipal_registration TEXT,
    tax_regime TEXT NOT NULL,
    postal_code TEXT NOT NULL,
    street TEXT NOT NULL,
    street_number TEXT NOT NULL,
    district TEXT NOT NULL,
    city TEXT NOT NULL,
    state TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS fiscal_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id INTEGER NOT NULL,
    budget_id INTEGER NOT NULL,
    issuer_id INTEGER NOT NULL,
    document_type TEXT NOT NULL CHECK (document_type IN ('nfe', 'nfse')),
    status TEXT NOT NULL DEFAULT 'rascunho_interno'
        CHECK (status = 'rascunho_interno'),
    issuer_name TEXT NOT NULL,
    issuer_cnpj TEXT NOT NULL,
    recipient_name TEXT NOT NULL,
    recipient_cnpj TEXT NOT NULL,
    total REAL NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (request_id, document_type),
    FOREIGN KEY (request_id) REFERENCES requests(id),
    FOREIGN KEY (budget_id) REFERENCES budgets(id),
    FOREIGN KEY (issuer_id) REFERENCES fiscal_issuers(id)
);
