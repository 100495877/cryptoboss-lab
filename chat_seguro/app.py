# chat_seguro/app.py
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from getpass import getpass
from datetime import datetime

# Núcleo propio
from core import auth
from core import crypto
from core import keystore

# Crypto primitives para firma (usadas aquí para no tocar tu crypto.py)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

# Rutas
ROOT = Path(__file__).resolve().parent.parent  # .../cryptoboss-lab/chat_seguro
DB_PATH = ROOT / "chat.db"
SCHEMA_PATH = ROOT / "chat_seguro" / "db" / "schema.sql"
KEYSTORE_DIR = ROOT / "keystore"  # guardamos aquí las privadas cifradas


# ==============================
# Utilidades de BD
# ==============================
def db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def audit(user: str | None, action: str, algo: str | None = None,
          key_bits: int | None = None, details: str | None = None) -> None:
    try:
        with db() as con:
            con.execute(
                "INSERT INTO audit(user,action,algo,key_bits,details) VALUES (?,?,?,?,?)",
                (user, action, algo, key_bits, details),
            )
    except Exception:
        # audit nunca debe romper el flujo principal
        pass


def get_user_pubkey_pem(username: str) -> bytes | None:
    with db() as con:
        cur = con.execute("SELECT pubkey_pem FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or not row[0]:
            return None
        # Está guardado como TEXT; convertir a bytes
        return row[0].encode("utf-8") if isinstance(row[0], str) else row[0]


def ensure_keystore_dir() -> None:
    KEYSTORE_DIR.mkdir(parents=True, exist_ok=True)


def user_privkey_path(username: str) -> Path:
    ensure_keystore_dir()
    return KEYSTORE_DIR / f"{username}.priv.blob"


# ==============================
# Inicialización de BD
# ==============================
def init_db(force: bool = False) -> None:
    """Crea la base de datos si no existe (o la recrea si force=True)."""
    if force and DB_PATH.exists():
        DB_PATH.unlink()
    if DB_PATH.exists() and not force:
        print(f"[DB] Ya existe en {DB_PATH}. Usa --force si quieres recrearla.")
        return
    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with sqlite3.connect(DB_PATH) as con:
        con.executescript(sql)
    print(f"[DB] Inicializada en {DB_PATH}")


# ==============================
# Comandos
# ==============================
def cmd_pki_init_root(_: argparse.Namespace) -> None:
    # Placeholder (para el Lab 2 o eval. siguiente)
    print("[PKI] init-root (pendiente de implementar)")
    audit(None, "PKI_INIT_ROOT")


def cmd_register(args: argparse.Namespace) -> None:
    username = args.user
    pwd1 = getpass("Introduce una contraseña: ")
    pwd2 = getpass("Repite la contraseña: ")
    if pwd1 != pwd2:
        print("[ERR] Las contraseñas no coinciden.")
        return

    ok = auth.register_user(username, pwd1)
    if not ok:
        return

    # Generar par RSA y guardar pública en BD; privada cifrada en keystore
    print("[KEYGEN] Generando par RSA 3072 bits…")
    priv, pub = crypto.generate_rsa_keypair(key_size=3072)

    pub_pem = crypto.serialize_public_key(pub).decode("utf-8")
    priv_blob_path = user_privkey_path(username)
    keystore.save_encrypted_private_key(
        private_key=priv,
        password=pwd1,
        username=username,
        storage_path=str(priv_blob_path),
    )

    with db() as con:
        con.execute(
            "UPDATE users SET pubkey_pem=? WHERE username=?",
            (pub_pem, username),
        )

    audit(username, "REGISTER", "RSA-PSS|RSA-OAEP|AES-256-GCM", 3072, f"priv={priv_blob_path.name}")
    print(f"[OK] Usuario '{username}' listo. Clave pública almacenada y privada cifrada en keystore.")


def cmd_login(args: argparse.Namespace) -> None:
    username = args.user
    pwd = getpass("Introduce tu contraseña: ")
    if auth.verify_login(username, pwd):
        audit(username, "LOGIN")
    # No mantenemos sesión persistente; el resto de comandos pedirá credenciales si las necesita.


def cmd_send(args: argparse.Namespace) -> None:
    # Para simplificar, pedimos el emisor aquí (no hay sesión global)
    sender = input("Tu usuario (emisor): ").strip()
    pwd = getpass("Tu contraseña: ")
    # Verificar credenciales antes de usar la privada
    if not auth.verify_login(sender, pwd):
        return

    recipient = args.to
    message = args.message

    # 1) Obtener pública del destinatario
    recipient_pub_pem = get_user_pubkey_pem(recipient)
    if not recipient_pub_pem:
        print(f"[ERR] El destinatario '{recipient}' no existe o no tiene clave pública.")
        return
    recipient_pub = crypto.load_public_key_from_pem(recipient_pub_pem)

    # 2) Cifrar mensaje con AES-256-GCM
    ciphertext, session_key, nonce, tag = crypto.encrypt_message_aes_gcm(message)

    # 3) Envolver la clave de sesión con RSA-OAEP (pública del destinatario)
    enc_key = crypto.encrypt_session_key_rsa_oaep(session_key, recipient_pub)

    # 4) Firmar el paquete con la privada del emisor (RSA-PSS)
    #    Cargamos la privada cifrada del keystore
    priv_blob_path = user_privkey_path(sender)
    if not priv_blob_path.exists():
        print(f"[ERR] El emisor '{sender}' no tiene clave privada en keystore.")
        return
    priv_blob = priv_blob_path.read_bytes()
    sender_priv = keystore.load_encrypted_private_key(priv_blob, pwd)

    signer_data = nonce + ciphertext + tag  # puedes ampliar con AAD si luego la añades
    signature = sender_priv.sign(
        signer_data,
        asy_padding.PSS(
            mgf=asy_padding.MGF1(hashes.SHA256()),
            salt_length=asy_padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    # 5) Guardar en BD
    with db() as con:
        con.execute(
            """
            INSERT INTO messages(sender,recipient,ciphertext,enc_key,nonce,tag,signature)
            VALUES (?,?,?,?,?,?,?)
            """,
            (sender, recipient, ciphertext, enc_key, nonce, tag, signature),
        )
    audit(sender, "SEND", "AES-256-GCM|RSA-OAEP|RSA-PSS", 3072, f"to={recipient}, bytes={len(ciphertext)}")
    print(f"[OK] Mensaje cifrado enviado a '{recipient}'.")


def cmd_inbox(_: argparse.Namespace) -> None:
    user = input("Usuario (destinatario): ").strip()
    with db() as con:
        cur = con.execute(
            "SELECT id, sender, created_at FROM messages WHERE recipient=? ORDER BY id DESC",
            (user,),
        )
        rows = cur.fetchall()
    if not rows:
        print("[INBOX] No hay mensajes.")
        return

    print(f"[INBOX] Mensajes para '{user}':")
    for mid, sender, ts in rows:
        print(f"  - id={mid}  de={sender}  fecha={ts}")


def cmd_read(args: argparse.Namespace) -> None:
    user = input("Tu usuario (destinatario): ").strip()
    pwd = getpass("Tu contraseña: ")

    msg_id = int(args.id)
    with db() as con:
        cur = con.execute(
            "SELECT sender, recipient, ciphertext, enc_key, nonce, tag, signature "
            "FROM messages WHERE id=?",
            (msg_id,),
        )
        row = cur.fetchone()

    if not row:
        print(f"[ERR] Mensaje id={msg_id} no existe.")
        return

    sender, recipient, ciphertext, enc_key, nonce, tag, signature = row
    if recipient != user:
        print(f"[ERR] Ese mensaje no es para '{user}'.")
        return

    # 1) Verificar firma con la pública del emisor
    sender_pub_pem = get_user_pubkey_pem(sender)
    if not sender_pub_pem:
        print(f"[ERR] El emisor '{sender}' no tiene clave pública registrada.")
        return
    sender_pub = crypto.load_public_key_from_pem(sender_pub_pem)

    verifier_data = nonce + ciphertext + tag
    try:
        sender_pub.verify(
            signature,
            verifier_data,
            asy_padding.PSS(
                mgf=asy_padding.MGF1(hashes.SHA256()),
                salt_length=asy_padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
    except Exception as e:
        print(f"[ERR] Firma inválida: {e}")
        return

    # 2) Cargar privada del destinatario y desenvolver la clave de sesión
    priv_blob_path = user_privkey_path(user)
    if not priv_blob_path.exists():
        print(f"[ERR] No encuentro la clave privada de '{user}' en keystore.")
        return
    priv_blob = priv_blob_path.read_bytes()
    user_priv = keystore.load_encrypted_private_key(priv_blob, pwd)

    session_key = crypto.decrypt_session_key_rsa_oaep(enc_key, user_priv)

    # 3) Descifrar el mensaje con AES-GCM
    try:
        plaintext = crypto.decrypt_message_aes_gcm(ciphertext, session_key, nonce, tag)
    except Exception as e:
        print(f"[ERR] Error al descifrar: {e}")
        return

    audit(user, "READ", "AES-256-GCM|RSA-OAEP|RSA-PSS", 3072, f"id={msg_id}, from={sender}")
    print("\n----- MENSAJE -----")
    print(plaintext)
    print("-------------------\n")


# ==============================
# Parser CLI
# ==============================
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chat-seguro",
        description="Chat seguro en Python (Criptografía UC3M)",
    )

    # Flag global: init-db
    parser.add_argument("--init-db", action="store_true",
                        help="Crea la base de datos si no existe")
    parser.add_argument("--force", action="store_true",
                        help="(con --init-db) Fuerza recreación de la base de datos")

    sub = parser.add_subparsers(dest="cmd")  # NOTA: sin required, para permitir solo --init-db

    # pki init-root
    pki_root = sub.add_parser("pki-init-root", help="Inicializa la CA raíz")
    pki_root.set_defaults(func=cmd_pki_init_root)

    # register
    register = sub.add_parser("register", help="Registra un nuevo usuario")
    register.add_argument("--user", required=True, help="Nombre de usuario")
    register.set_defaults(func=cmd_register)

    # login
    login = sub.add_parser("login", help="Inicia sesión (verificación de credenciales)")
    login.add_argument("--user", required=True)
    login.set_defaults(func=cmd_login)

    # send
    send = sub.add_parser("send", help="Envía un mensaje cifrado")
    send.add_argument("--to", required=True, help="Destinatario")
    send.add_argument("--message", required=True, help="Texto del mensaje")
    send.set_defaults(func=cmd_send)

    # inbox
    inbox = sub.add_parser("inbox", help="Muestra bandeja de entrada")
    inbox.set_defaults(func=cmd_inbox)

    # read
    read = sub.add_parser("read", help="Lee y descifra un mensaje")
    read.add_argument("--id", type=int, required=True, help="ID del mensaje")
    read.set_defaults(func=cmd_read)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    # Permitir ejecutar solo --init-db (opcionalmente con --force)
    if args.init_db:
        init_db(force=getattr(args, "force", False))
        # si no hay subcomando, terminamos aquí
        if args.cmd is None:
            return 0

    # Ejecutar subcomando (si lo hay)
    if hasattr(args, "func"):
        args.func(args)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
