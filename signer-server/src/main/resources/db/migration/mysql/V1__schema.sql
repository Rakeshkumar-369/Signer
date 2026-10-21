-- MySQL 8 / MariaDB 10.6+
CREATE TABLE tenants (
    id              VARCHAR(36)   PRIMARY KEY,
    code            VARCHAR(64)   NOT NULL UNIQUE,
    name            VARCHAR(200)  NOT NULL,
    contact_email   VARCHAR(200),
    status          VARCHAR(16)   NOT NULL,
    plan            VARCHAR(64)   NOT NULL,
    monthly_quota   BIGINT        NOT NULL,
    valid_until     DATETIME(6),
    allowed_origins VARCHAR(2000) NOT NULL,
    created_at      DATETIME(6)   NOT NULL,
    updated_at      DATETIME(6)   NOT NULL
);

CREATE TABLE api_keys (
    id           VARCHAR(36)  PRIMARY KEY,
    tenant_id    VARCHAR(36)  NOT NULL REFERENCES tenants (id),
    label        VARCHAR(100) NOT NULL,
    prefix       VARCHAR(16)  NOT NULL,
    key_hash     VARCHAR(64)  NOT NULL UNIQUE,
    created_at   DATETIME(6)  NOT NULL,
    last_used_at DATETIME(6),
    revoked_at   DATETIME(6)
);

CREATE TABLE transactions (
    id            VARCHAR(36)  PRIMARY KEY,
    tenant_id     VARCHAR(36)  NOT NULL REFERENCES tenants (id),
    origin        VARCHAR(255) NOT NULL,
    operations    VARCHAR(100) NOT NULL,
    max_documents INT          NOT NULL,
    reference     VARCHAR(255),
    status        VARCHAR(16)  NOT NULL,
    issued_at     DATETIME(6)  NOT NULL,
    expires_at    DATETIME(6)  NOT NULL,
    completed_at  DATETIME(6),
    documents     INT          NOT NULL DEFAULT 0,
    signer_name   VARCHAR(255),
    signer_serial VARCHAR(100),
    document_hash VARCHAR(128),
    client_ip     VARCHAR(64),
    error         VARCHAR(500)
);
CREATE INDEX idx_transactions_tenant_issued ON transactions (tenant_id, issued_at);
CREATE INDEX idx_transactions_issued ON transactions (issued_at);

CREATE TABLE signing_sessions (
    id            VARCHAR(36)  PRIMARY KEY,
    tenant_id     VARCHAR(36)  NOT NULL REFERENCES tenants (id),
    txn           VARCHAR(36),
    status        VARCHAR(16)  NOT NULL,
    document_name VARCHAR(255),
    digest        VARCHAR(64)  NOT NULL,
    certificate   TEXT,
    timestamp_req BOOLEAN      NOT NULL,
    ltv_req       BOOLEAN      NOT NULL,
    prepared_pdf  LONGBLOB,
    created_at    DATETIME(6)  NOT NULL,
    expires_at    DATETIME(6)  NOT NULL
);
CREATE INDEX idx_sessions_expires ON signing_sessions (expires_at);

CREATE TABLE admin_users (
    id                   VARCHAR(36)  PRIMARY KEY,
    username             VARCHAR(64)  NOT NULL UNIQUE,
    password_hash        VARCHAR(100) NOT NULL,
    role                 VARCHAR(16)  NOT NULL,
    must_change_password BOOLEAN      NOT NULL,
    created_at           DATETIME(6)  NOT NULL,
    last_login_at        DATETIME(6)
);

CREATE TABLE audit_log (
    id     VARCHAR(36)   PRIMARY KEY,
    occurred_at DATETIME(6)   NOT NULL,
    actor  VARCHAR(100)  NOT NULL,
    action VARCHAR(64)   NOT NULL,
    target VARCHAR(255),
    detail VARCHAR(1000),
    ip     VARCHAR(64)
);
CREATE INDEX idx_audit_at ON audit_log (occurred_at);

CREATE TABLE settings (
    setting_key   VARCHAR(64) PRIMARY KEY,
    setting_value MEDIUMTEXT NOT NULL
);
