# chat_seguro/app.py
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from getpass import getpass
from chat_seguro.core import auth, crypto, sign, keystore, pki

# Rutas
ROOT = Path(__file__).resolve().parent.parent
DB_PATH = ROOT / "chat.db"
SCHEMA_PATH = ROOT / "chat_seguro" / "db" / "schema.sql"



# Utilidades de BD

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


def get_user_encrypted_privkey(username: str) -> bytes | None:
    """Obtiene la clave privada cifrada de un usuario desde la BD."""
    with db() as con:
        cur = con.execute("SELECT encrypted_private_key FROM users WHERE username=?", (username,))
        row = cur.fetchone()
        if not row or not row[0]:
            return None
        return row[0]


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



# COMANDOS


def cmd_pki_init_root(args: argparse.Namespace) -> None:
    """Inicializa la CA raíz de la PKI."""
    print("[PKI] Inicializando CA raíz...")
    
    # Verificar si ya existe
    try:
        test_pwd = getpass("Contraseña para la CA raíz (si ya existe, cancela con Ctrl+C): ")
        pki.load_ca_from_db(DB_PATH, test_pwd)
        print("[PKI] ⚠️  La CA raíz ya existe y la contraseña es correcta.")
        return
    except (ValueError, KeyboardInterrupt):
        pass
    
    ca_pwd1 = getpass("Introduce contraseña para la CA raíz: ")
    ca_pwd2 = getpass("Repite la contraseña: ")
    
    if ca_pwd1 != ca_pwd2:
        print("[ERR] Las contraseñas no coinciden.")
        return
    
    try:
        pki.init_pki(DB_PATH, ca_pwd1)
        audit(None, "PKI_INIT_ROOT", "RSA-4096|X509v3", 4096, "CA raíz creada")
        print("[OK] CA raíz inicializada correctamente.")
    except Exception as e:
        print(f"[ERR] Error al inicializar PKI: {e}")
        audit(None, "PKI_INIT_ROOT_FAILED", details=str(e))


def cmd_register(args: argparse.Namespace) -> None:
    """Registra un nuevo usuario con claves RSA cifradas."""
    username = args.user
    pwd1 = getpass("Introduce una contraseña: ")
    pwd2 = getpass("Repite la contraseña: ")
    
    if pwd1 != pwd2:
        print("[ERR] Las contraseñas no coinciden.")
        return

    ok = auth.register_user(username, pwd1)
    if not ok:
        return

    # Generar par RSA
    print("[KEYGEN] Generando par RSA 3072 bits…")
    priv, pub = crypto.generate_rsa_keypair(key_size=3072)
    pub_pem = crypto.serialize_public_key(pub).decode("utf-8")

    # Cifrar la clave privada con la contraseña del usuario
    print("[KEYSTORE] Cifrando clave privada con tu contraseña...")
    encrypted_blob = keystore.save_encrypted_private_key(
        priv, pwd1, username, storage_path=None
    )

    # Guardar pública y privada cifrada en BD
    with db() as con:
        con.execute(
            "UPDATE users SET pubkey_pem=?, encrypted_private_key=? WHERE username=?",
            (pub_pem, encrypted_blob, username),
        )

    audit(username, "REGISTER", "RSA-PSS|RSA-OAEP|AES-256-GCM|AES-256-CBC", 3072,
          "privkey_encrypted=True")
    print(f"[OK] Usuario '{username}' registrado. Clave privada cifrada en BD.")
    print(f"[INFO] Usa 'pki-issue --user {username}' para solicitar un certificado X.509.")


def cmd_login(args: argparse.Namespace) -> None:
    """Verifica las credenciales de un usuario."""
    username = args.user
    pwd = getpass("Introduce tu contraseña: ")
    if auth.verify_login(username, pwd):
        audit(username, "LOGIN")


def cmd_pki_issue(args: argparse.Namespace) -> None:
    """Emite un certificado X.509 para un usuario."""
    username = args.user
    
    # Verificar que el usuario existe
    with db() as con:
        cur = con.execute("SELECT encrypted_private_key FROM users WHERE username=?", (username,))
        row = cur.fetchone()
    
    if not row or not row[0]:
        print(f"[ERR] El usuario '{username}' no existe o no tiene claves generadas.")
        print(f"[INFO] Primero debe registrarse con 'register --user {username}'")
        return
    
    encrypted_privkey = row[0]
    
    # Pedir contraseña del usuario para descifrar su clave privada
    user_pwd = getpass(f"Contraseña de '{username}': ")
    try:
        user_priv = keystore.load_encrypted_private_key(encrypted_privkey, user_pwd)
    except ValueError as e:
        print(f"[ERR] No se pudo descifrar la clave privada: {e}")
        return
    
    # Pedir contraseña de la CA
    ca_pwd = getpass("Contraseña de la CA raíz: ")
    
    # Email opcional
    email = input(f"Email para '{username}' (opcional, Enter para omitir): ").strip() or None
    
    try:
        cert = pki.issue_user_certificate(DB_PATH, username, user_priv, ca_pwd, email)
        audit(username, "PKI_ISSUE_CERT", "RSA-3072|X509v3", 3072, f"cert_serial={cert.serial_number}")
        print(f"[OK] Certificado emitido para '{username}'.")
    except Exception as e:
        print(f"[ERR] Error al emitir certificado: {e}")
        audit(username, "PKI_ISSUE_CERT_FAILED", details=str(e))


def cmd_send(args: argparse.Namespace) -> None:
    """Envía un mensaje cifrado y firmado."""
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

    # 3) Envolver la clave de sesión con RSA-OAEP
    enc_key = crypto.encrypt_session_key_rsa_oaep(session_key, recipient_pub)

    # 4) Cargar clave privada cifrada del emisor
    encrypted_privkey = get_user_encrypted_privkey(sender)
    if not encrypted_privkey:
        print(f"[ERR] No se encontró la clave privada cifrada de '{sender}'.")
        return

    try:
        sender_priv = keystore.load_encrypted_private_key(encrypted_privkey, pwd)
    except ValueError as e:
        print(f"[ERR] No se pudo descifrar la clave privada: {e}")
        return

    # 5) Firmar con sign.py
    signature = sign.sign_message_package(sender_priv, nonce, ciphertext, tag)

    # 6) Guardar en BD
    with db() as con:
        con.execute(
            """
            INSERT INTO messages(sender,recipient,ciphertext,enc_key,nonce,tag,signature)
            VALUES (?,?,?,?,?,?,?)
            """,
            (sender, recipient, ciphertext, enc_key, nonce, tag, signature),
        )

    audit(sender, "SEND", "AES-256-GCM|RSA-OAEP|RSA-PSS", 3072, f"to={recipient}")
    print(f"[OK] Mensaje cifrado y firmado enviado a '{recipient}'.")


def cmd_inbox(_: argparse.Namespace) -> None:
    """Muestra la bandeja de entrada de un usuario."""
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
    """Lee y descifra un mensaje, verificando firma y certificado."""
    user = input("Tu usuario (destinatario): ").strip()
    pwd = getpass("Tu contraseña: ")
    if not auth.verify_login(user, pwd):
        return

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

    # 1) Verificar firma con sign.py
    sender_pub_pem = get_user_pubkey_pem(sender)
    if not sender_pub_pem:
        print(f"[ERR] El emisor '{sender}' no tiene clave pública registrada.")
        return
    sender_pub = crypto.load_public_key_from_pem(sender_pub_pem)

    if not sign.verify_message_package(sender_pub, nonce, ciphertext, tag, signature):
        print(f"[ERR] ⚠️  Firma inválida. El mensaje puede haber sido manipulado.")
        return
    print("[OK] ✓ Firma verificada correctamente.")

    # 2) Verificar certificado del emisor (si existe)
    try:
        sender_cert = pki.load_user_certificate(DB_PATH, sender)
        if sender_cert:
            ca_pwd = getpass("Contraseña de la CA (para verificar certificado): ")
            try:
                ca_private_key, ca_cert = pki.load_ca_from_db(DB_PATH, ca_pwd)
                is_valid, msg = pki.verify_certificate(sender_cert, ca_cert)
                if is_valid:
                    print(f"[OK] ✓ Certificado del emisor válido.")
                else:
                    print(f"[WARN] ⚠️  Certificado del emisor inválido: {msg}")
            except ValueError:
                print(f"[WARN] Contraseña de CA incorrecta, no se pudo verificar certificado.")
        else:
            print(f"[WARN] El emisor no tiene certificado X.509.")
    except Exception as e:
        print(f"[WARN] No se pudo verificar el certificado: {e}")

    # 3) Cargar clave privada cifrada del destinatario
    encrypted_privkey = get_user_encrypted_privkey(user)
    if not encrypted_privkey:
        print(f"[ERR] No se encontró la clave privada cifrada de '{user}'.")
        return

    try:
        user_priv = keystore.load_encrypted_private_key(encrypted_privkey, pwd)
    except ValueError as e:
        print(f"[ERR] No se pudo descifrar la clave privada: {e}")
        return

    # 4) Descifrar clave de sesión y mensaje
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



# PARSER CLI


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

    # PKI
    pki_root = sub.add_parser("pki-init-root", help="Inicializa la CA raíz")
    pki_root.set_defaults(func=cmd_pki_init_root)
    
    pki_issue = sub.add_parser("pki-issue", help="Emite un certificado X.509 para un usuario")
    pki_issue.add_argument("--user", required=True)
    pki_issue.set_defaults(func=cmd_pki_issue)

    # Usuarios
    register = sub.add_parser("register", help="Registra un nuevo usuario")
    register.add_argument("--user", required=True)
    register.set_defaults(func=cmd_register)

    login = sub.add_parser("login", help="Inicia sesión (verificación de credenciales)")
    login.add_argument("--user", required=True)
    login.set_defaults(func=cmd_login)

    # Mensajes
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