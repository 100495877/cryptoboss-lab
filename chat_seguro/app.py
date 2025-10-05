from __future__ import annotations

from core import auth
import argparse
import sqlite3
from pathlib import Path
import sys


# Rutas
ROOT = Path(__file__).resolve().parent.parent  # .../cryptoboss-lab/chat_seguro
DB_PATH = ROOT / "chat.db"
SCHEMA_PATH = ROOT / "chat_seguro" / "db" / "schema.sql"


def init_db(force: bool = False) -> None:
    """Crea la base de datos si no existe (o la recrea si force=True)."""
    if force and DB_PATH.exists():
        DB_PATH.unlink()
    create = (not DB_PATH.exists()) or force
    if not create:
        return

    sql = SCHEMA_PATH.read_text(encoding="utf-8")
    with sqlite3.connect(DB_PATH) as con:
        con.executescript(sql)
    print(f"[DB] Inicializada en {DB_PATH}")


def cmd_pki_init_root(args: argparse.Namespace) -> None:
    # TODO: Implementar generación de CA raíz (Módulo PKI)
    print("[PKI] init-root (pendiente de implementar)")


def cmd_register(args):
    password = input("Introduce una contraseña: ")
    auth.register_user(args.user, password)


def cmd_login(args):
    password = input("Introduce tu contraseña: ")
    auth.verify_login(args.user, password)


def cmd_send(args: argparse.Namespace) -> None:
    # TODO: AES-GCM + RSA-OAEP + firma RSA-PSS
    print(f"[MSG] send to={args.to} msg='{args.message}' (pendiente de implementar)")


def cmd_inbox(args: argparse.Namespace) -> None:
    # TODO: Listar mensajes para el usuario autenticado
    print("[MSG] inbox (pendiente de implementar)")


def cmd_read(args: argparse.Namespace) -> None:
    # TODO: Verificar firma, validar certificado, descifrar
    print(f"[MSG] read id={args.id} (pendiente de implementar)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chat-seguro",
        description="Chat seguro en Python (Criptografía UC3M)"
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # pki init-root
    pki_root = sub.add_parser("pki-init-root", help="Inicializa la CA raíz")
    pki_root.set_defaults(func=cmd_pki_init_root)

    # register
    register = sub.add_parser("register", help="Registra un nuevo usuario")
    register.add_argument("--user", required=True, help="Nombre de usuario")
    register.set_defaults(func=cmd_register)

    # login
    login = sub.add_parser("login", help="Inicia sesión")
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
    read.add_argument("--id", required=True, help="ID del mensaje")
    read.set_defaults(func=cmd_read)

    # global flags
    parser.add_argument("--init-db", action="store_true",
                        help="Crea la base de datos si no existe")

    return parser


def main(argv: list[str] | None = None) -> int:
    argv = argv or sys.argv[1:]
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.init_db:
        init_db()

    # Ejecutar el comando correspondiente
    if hasattr(args, "func"):
        args.func(args)
        return 0
    else:
        parser.print_help()
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
