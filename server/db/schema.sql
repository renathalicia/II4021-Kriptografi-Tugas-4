-- Tabel metadata users

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    created_at TEXT NOT NULL
);

-- Vault disimpan sebagai BLOB agar server tidak bisa baca isinya
-- server_share disimpan sebagai text format JSON
CREATE TABLE IF NOT EXISTS vaults (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    encrypted_vault BLOB NOT NULL,
    vault_nonce BLOB NOT NULL,
    vault_tag BLOB NOT NULL,
    server_share TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);