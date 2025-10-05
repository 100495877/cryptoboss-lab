-- Esquema inicial SQLite para Chat Seguro

CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT UNIQUE NOT NULL,
    pwd_hash   TEXT NOT NULL,
    cert_pem   TEXT,         -- certificado X.509 del usuario (PEM)
    pubkey_pem TEXT,         -- clave pública (si la guardamos aparte)
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS messages(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender     TEXT NOT NULL,
    recipient  TEXT NOT NULL,
    ciphertext BLOB NOT NULL, -- texto cifrado (AES-GCM)
    enc_key    BLOB NOT NULL, -- clave de sesión cifrada con RSA-OAEP
    nonce      BLOB NOT NULL, -- nonce/IV del AES-GCM
    tag        BLOB NOT NULL, -- autenticación de GCM
    signature  BLOB NOT NULL, -- firma RSA-PSS del emisor
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS pki_certs(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject    TEXT NOT NULL,
    pem        TEXT NOT NULL, -- certificado en PEM
    issuer     TEXT NOT NULL,
    is_ca      INTEGER DEFAULT 0, -- 1 si es CA
    valid_from TEXT,
    valid_to   TEXT
);

CREATE TABLE IF NOT EXISTS audit(
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user     TEXT,
    action   TEXT,  -- e.g. 'REGISTER','SEND','READ','PKI_ISSUE'
    algo     TEXT,  -- e.g. 'AES-256-GCM','RSA-OAEP-2048'
    key_bits INTEGER,
    details  TEXT,
    ts       TEXT DEFAULT CURRENT_TIMESTAMP
);
