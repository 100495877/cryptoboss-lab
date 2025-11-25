"""
Módulo de acceso a la base de datos SQLite.
Gestiona usuarios, mensajes, certificados PKI y auditoría.
"""

import sqlite3
import os
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager



#  CONFIGURACIÓN

DB_PATH = os.path.join(os.path.dirname(__file__), '..', 'db', 'chat.db')
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '..', 'db', 'schema.sql')



#  GESTIÓN DE CONEXIONES

@contextmanager
def get_connection():
    """
    Context manager para manejar conexiones a la base de datos
    Uso:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(...)
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Permitir acceso por nombre de columna
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        conn.close()


def init_database():
    """
    Inicializa la base de datos ejecutando el schema.sql
    """
    if not os.path.exists(SCHEMA_PATH):
        raise FileNotFoundError(f"No se encuentra el archivo schema.sql en {SCHEMA_PATH}")
    
    with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
        schema_sql = f.read()
    
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.executescript(schema_sql)
    
    print(f"[DB] Base de datos inicializada en {DB_PATH}")


#  TABLA: USERS

def create_user(username: str, pwd_hash: str, encrypted_private_key: bytes,
                pubkey_pem: bytes, cert_pem: Optional[bytes] = None) -> int:
    """
    Crea un nuevo usuario en la base de datos
    
    Argumentos:
        username: Nombre de usuario 
        pwd_hash: Hash de la contraseña (bcrypt o PBKDF2)
        encrypted_private_key: Clave privada RSA cifrada (formato blob)
        pubkey_pem: Clave pública RSA en formato PEM
        cert_pem: Certificado X.509 en formato PEM (opcional)
    
    Returns:
        ID del usuario creado
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO users (username, pwd_hash, encrypted_private_key, pubkey_pem, cert_pem)
            VALUES (?, ?, ?, ?, ?)
        """, (username, pwd_hash, encrypted_private_key, pubkey_pem, cert_pem))
        return cursor.lastrowid


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """
    Obtiene un usuario por su nombre de usuario.
    
    Returns:
        Diccionario con los datos del usuario o None si no existe
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """
    Obtiene un usuario por su ID.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def update_user_certificate(username: str, cert_pem: bytes) -> None:
    """
    Actualiza el certificado X.509 de un usuario
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE users SET cert_pem = ? WHERE username = ?
        """, (cert_pem, username))


def user_exists(username: str) -> bool:
    """
    Verifica si un usuario existe.
    """
    return get_user_by_username(username) is not None


def list_all_users() -> List[Dict[str, Any]]:
    """
    Lista todos los usuarios registrados
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, created_at FROM users ORDER BY username")
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


#  TABLA: MESSAGES

def create_message(sender: str, recipient: str, ciphertext: bytes,
                   enc_key: bytes, nonce: bytes, tag: bytes,
                   signature: bytes) -> int:
    """
    Guarda un mensaje cifrado en la base de datos.
    
    Argumentos:
        sender: Usuario que envía el mensaje
        recipient: Usuario que recibe el mensaje
        ciphertext: Mensaje cifrado con AES-GCM
        enc_key: Clave de sesión AES cifrada con RSA-OAEP
        nonce: Nonce usado en AES-GCM (12 bytes)
        tag: Tag de autenticación de AES-GCM (16 bytes)
        signature: Firma digital RSA-PSS del mensaje
    
    Returns:
        ID del mensaje creado
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO messages (sender, recipient, ciphertext, enc_key, nonce, tag, signature)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (sender, recipient, ciphertext, enc_key, nonce, tag, signature))
        return cursor.lastrowid


def get_message_by_id(message_id: int) -> Optional[Dict[str, Any]]:
    """
    Obtiene un mensaje por su ID.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM messages WHERE id = ?", (message_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_inbox(username: str) -> List[Dict[str, Any]]:
    """
    Obtiene todos los mensajes recibidos por un usuario.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM messages 
            WHERE recipient = ? 
            ORDER BY created_at DESC
        """, (username,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_sent_messages(username: str) -> List[Dict[str, Any]]:
    """
    Obtiene todos los mensajes enviados por un usuario.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM messages 
            WHERE sender = ? 
            ORDER BY created_at DESC
        """, (username,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def delete_message(message_id: int) -> None:
    """
    Elimina un mensaje de la base de datos.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM messages WHERE id = ?", (message_id,))


def count_unread_messages(username: str) -> int:
    """
    Cuenta los mensajes no leídos de un usuario.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT COUNT(*) as count FROM messages 
            WHERE recipient = ?
        """, (username,))
        row = cursor.fetchone()
        return row['count'] if row else 0


#  TABLA: PKI_CERTS

def create_pki_certificate(subject: str, pem: bytes, issuer: str,
                           is_ca: bool, valid_from: str, valid_to: str) -> int:
    """
    Guarda un certificado X.509 en la PKI.
    
    Argumentos:
        subject: Nombre del sujeto del certificado
        pem: Certificado en formato PEM
        issuer: Nombre del emisor del certificado
        is_ca: True si es un certificado de CA
        valid_from: Fecha de inicio de validez (formato ISO)
        valid_to: Fecha de fin de validez (formato ISO)
    
    Returns:
        ID del certificado creado
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO pki_certs (subject, pem, issuer, is_ca, valid_from, valid_to)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (subject, pem, issuer, is_ca, valid_from, valid_to))
        return cursor.lastrowid


def get_certificate_by_subject(subject: str) -> Optional[Dict[str, Any]]:
    """
    Obtiene un certificado por el nombre del sujeto.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM pki_certs WHERE subject = ?", (subject,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_ca_certificates() -> List[Dict[str, Any]]:
    """
    Obtiene todos los certificados de CA (raíz y subordinadas).
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM pki_certs 
            WHERE is_ca = 1 
            ORDER BY subject
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def list_all_certificates() -> List[Dict[str, Any]]:
    """
    Lista todos los certificados almacenados.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, subject, issuer, is_ca, valid_from, valid_to 
            FROM pki_certs 
            ORDER BY subject
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


# ==============================
#  TABLA: AUDIT
# ==============================
def log_audit(user: str, action: str, algo: str, key_bits: int,
              details: Optional[str] = None) -> int:
    """
    Registra una acción criptográfica en el log de auditoría.
    
    Argumentos:
        user: Usuario que realiza la acción
        action: Descripción de la acción (ej: "ENCRYPT_MESSAGE", "SIGN_MESSAGE")
        algo: Algoritmo usado (ej: "AES-256-GCM", "RSA-PSS-2048")
        key_bits: Tamaño de clave en bits
        details: Información adicional opcional
    
    Returns:
        ID del registro de auditoría
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO audit (user, action, algo, key_bits, details)
            VALUES (?, ?, ?, ?, ?)
        """, (user, action, algo, key_bits, details))
        return cursor.lastrowid


def get_audit_logs(limit: int = 100, user: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Obtiene los logs de auditoría.
    
    Argumentos:
        limit: Número máximo de registros a devolver
        user: Filtrar por usuario (opcional)
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        if user:
            cursor.execute("""
                SELECT * FROM audit 
                WHERE user = ? 
                ORDER BY ts DESC 
                LIMIT ?
            """, (user, limit))
        else:
            cursor.execute("""
                SELECT * FROM audit 
                ORDER BY ts DESC 
                LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_audit_logs_by_action(action: str, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Obtiene logs de auditoría filtrados por tipo de acción.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM audit 
            WHERE action = ? 
            ORDER BY ts DESC 
            LIMIT ?
        """, (action, limit))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


# ==============================
#  UTILIDADES
# ==============================
def database_exists() -> bool:
    """
    Verifica si la base de datos existe.
    """
    return os.path.exists(DB_PATH)


def get_database_stats() -> Dict[str, int]:
    """
    Obtiene estadísticas de la base de datos.
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) as count FROM users")
        users_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM messages")
        messages_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM pki_certs")
        certs_count = cursor.fetchone()['count']
        
        cursor.execute("SELECT COUNT(*) as count FROM audit")
        audit_count = cursor.fetchone()['count']
        
        return {
            'users': users_count,
            'messages': messages_count,
            'certificates': certs_count,
            'audit_logs': audit_count
        }


def clear_all_messages() -> int:
    """
    Elimina todos los mensajes de la base de datos.
    Útil para testing.
    
    Returns:
        Número de mensajes eliminados
    """
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM messages")
        count = cursor.fetchone()['count']
        cursor.execute("DELETE FROM messages")
        return count


#  INICIALIZACIÓN

def ensure_database_initialized():
    """
    Asegura que la base de datos está inicializada.
    Si no existe, la crea.
    """
    if not database_exists():
        print("[DB] Base de datos no encontrada. Inicializando...")
        init_database()
    else:
        print(f"[DB] Base de datos cargada desde {DB_PATH}")