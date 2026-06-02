import sqlite3
import os
import server.config as config

def get_connection() -> sqlite3.Connection:
    # buat folder data/jika belum ada
    os.makedirs(os.path.dirname(config.DATABASE_PATH), exist_ok=True)
    conn = sqlite3.connect(config.DATABASE_PATH)
    # row factory agar hasil query bisa diakses dengan nama kolom
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")  
    return conn

def init_db():
    """Baca schema.sql dan buat tabel"""
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path) as f:
        schema = f.read()
    with get_connection() as conn:
        conn.executescript(schema)