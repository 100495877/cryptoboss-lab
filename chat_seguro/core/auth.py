import sqlite3
from pathlib import Path
import bcrypt

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "chat.db"


def get_connection():
    """Devuelve una conexión SQLite abierta (usa context manager en cada operación)."""
    return sqlite3.connect(DB_PATH)


# ==============================
#  REGISTRO DE USUARIO
# ==============================
def register_user(username: str, password: str) -> bool:
    """Registra un nuevo usuario con contraseña hasheada."""
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    pwd_hash = bcrypt.hashpw(pwd_bytes, salt)

    try:
        with get_connection() as con:
            cur = con.cursor()
            cur.execute(
                "INSERT INTO users (username, pwd_hash) VALUES (?, ?)",
                (username, pwd_hash),
            )
            con.commit()
        print(f"[OK] Usuario '{username}' registrado correctamente.")
        return True
    except sqlite3.IntegrityError:
        print(f"[ERR] El usuario '{username}' ya existe.")
        return False


# ==============================
#  LOGIN DE USUARIO
# ==============================
def verify_login(username: str, password: str) -> bool:
    """Verifica la contraseña del usuario."""
    with get_connection() as con:
        cur = con.cursor()
        cur.execute("SELECT pwd_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()

    if not row:
        print(f"[ERR] El usuario '{username}' no existe.")
        return False

    stored_hash = row[0]
    if bcrypt.checkpw(password.encode("utf-8"), stored_hash):
        print(f"[OK] Login correcto para '{username}'.")
        return True
    else:
        print("[ERR] Contraseña incorrecta.")
        return False
