# chat_seguro/app.py
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from getpass import getpass
from core import auth
from core import crypto
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asy_padding

# Rutas
ROOT = Path(__file__).resolve().parent.parent  # .../cryptoboss-lab/chat_seguro
DB_PATH = ROOT / "chat.db"
SCHEMA_PATH = ROOT / "chat_seguro" / "db" / "schema.sql"


# ==============================
# Utilidades de BD
# ==============================
def db() -> sqlite3.Connection:
    return sqlite3.connect(DB_PATH)


def audit(user: str | None, action: str, algo: str | None = None,
          key_bits: int | None = None, details: str | None = None) -> None:
    """Registra eventos en la tabla audit (no interrumpe el flujo principal)."""
    try:
        with db() as con:
            con.execute(
                "INSERT INTO audit(user,action,algo,key_bits,details) VALUES (?,?,?,?,?)",
                (user, action, algo, key_bits, details),
            )
    except Exception:
        pass


def get_user_pubkey_pem(username: str) -> bytes | None:
    """Obtiene la clave pública de un usuario en formato PEM."""
    with db() as con:
        cur = con.execute("SELECT pubkey_pem FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or not row[0]:
            return None
        return row[0].encode("utf-8") if isinstance(row[0], str) else row[0]


# Inicialización de BD
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


# Comandos
def cmd_pki_init_root(_: argparse.Namespace) -> None:
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

    # Generar par RSA y guardar pública/privada en PEM
    print("[KEYGEN] Generando par RSA 3072 bits…")
    priv, pub = crypto.generate_rsa_keypair(key_size=3072)

    pub_pem = crypto.serialize_public_key(pub).decode("utf-8")
    priv_pem = crypto.serialize_private_key(priv).decode("utf-8")

    # Guardar pública en BD
    with db() as con:
        con.execute(
            "UPDATE users SET pubkey_pem=? WHERE username=?",
            (pub_pem, username),
        )

    # Guardar privada sin cifrar (solo Lab1)
    priv_path = Path(f"{username}_private.pem")
    priv_path.write_text(priv_pem)
    print(f"[OK] Clave privada guardada en {priv_path}")

    audit(username, "REGISTER", "RSA-PSS|RSA-OAEP|AES-256-GCM", 3072, f"priv={priv_path.name}")
    print(f"[OK] Usuario '{username}' registrado y listo.")


def cmd_login(args: argparse.Namespace) -> None:
    username = args.user
    pwd = getpass("Introduce tu contraseña: ")
    if auth.verify_login(username, pwd):
        audit(username, "LOGIN")


def cmd_send(args: argparse.Namespace) -> None:
    sender = input("Tu usuario (emisor): ").strip()
    pwd = getpass("Tu contraseña: ")
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

    # 4) Firmar el paquete con la privada del emisor
    priv_path = Path(f"{sender}_private.pem")
    if not priv_path.exists():
        print(f"[ERR] No se encontró la clave privada de '{sender}' ({priv_path}).")
        return
    priv_pem = priv_path.read_text()
    sender_priv = crypto.load_private_key_from_pem(priv_pem.encode())

    signer_data = nonce + ciphertext + tag
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

    audit(sender, "SEND", "AES-256-GCM|RSA-OAEP|RSA-PSS", 3072, f"to={recipient}")
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

    # 1) Verificar firma
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

    # 2) Cargar privada del destinatario
    priv_path = Path(f"{user}_private.pem")
    if not priv_path.exists():
        print(f"[ERR] No se encontró la clave privada de '{user}' ({priv_path}).")
        return
    priv_pem = priv_path.read_text()
    user_priv = crypto.load_private_key_from_pem(priv_pem.encode())

    # 3) Descifrar clave de sesión y mensaje
    session_key = crypto.decrypt_session_key_rsa_oaep(enc_key, user_priv)
    try:
        plaintext = crypto.decrypt_message_aes_gcm(ciphertext, session_key, nonce, tag)
    except Exception as e:
        print(f"[ERR] Error al descifrar: {e}")
        return

    audit(user, "READ", "AES-256-GCM|RSA-OAEP|RSA-PSS", 3072, f"id={msg_id}, from={sender}")
    print("\n----- MENSAJE -----")
    print(plaintext)
    print("-------------------\n")


# Parser CLI
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chat-seguro",
        description="Chat seguro en Python (Criptografía UC3M)",
    )

    parser.add_argument("--init-db", action="store_true",
                        help="Crea la base de datos si no existe")
    parser.add_argument("--force", action="store_true",
                        help="(con --init-db) Fuerza recreación de la base de datos")

    sub = parser.add_subparsers(dest="cmd")

    pki_root = sub.add_parser("pki-init-root", help="Inicializa la CA raíz")
    pki_root.set_defaults(func=cmd_pki_init_root)

    register = sub.add_parser("register", help="Registra un nuevo usuario")
    register.add_argument("--user", required=True)
    register.set_defaults(func=cmd_register)

    login = sub.add_parser("login", help="Inicia sesión (verificación de credenciales)")
    login.add_argument("--user", required=True)
    login.set_defaults(func=cmd_login)

    send = sub.add_parser("send", help="Envía un mensaje cifrado")
    send.add_argument("--to", required=True)
    send.add_argument("--message", required=True)
    send.set_defaults(func=cmd_send)

    inbox = sub.add_parser("inbox", help="Muestra bandeja de entrada")
    inbox.set_defaults(func=cmd_inbox)

    read = sub.add_parser("read", help="Lee y descifra un mensaje")
    read.add_argument("--id", type=int, required=True)
    read.set_defaults(func=cmd_read)

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.init_db:
        init_db(force=getattr(args, "force", False))
        if args.cmd is None:
            return 0

    if hasattr(args, "func"):
        args.func(args)
        return 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
