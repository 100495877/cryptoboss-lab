"""
Módulo de gestión segura de claves privadas.
- AES-256-CBC: cifrado de claves privadas RSA en reposo
- PBKDF2: derivación de clave de cifrado desde contraseña
- HMAC-SHA256: verificación de integridad
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from .crypto import derive_key_from_password


# ==============================
#  CIFRADO DE CLAVES PRIVADAS
# ==============================
def encrypt_private_key(private_key, password: str) -> dict:
    """
    Cifra una clave privada RSA con AES-256-CBC usando una contraseña.

    Args:
        private_key: Objeto clave privada RSA
        password: Contraseña del usuario para derivar la clave de cifrado

    Returns:
        dict con:
            - salt: sal para PBKDF2 (16 bytes)
            - iv: vector de inicialización para AES-CBC (16 bytes)
            - ciphertext: clave privada cifrada
            - hmac: tag de autenticación HMAC-SHA256 (32 bytes)
    """
    # 1. Serializar la clave privada a PEM (sin cifrar)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Generar sal aleatoria para PBKDF2
    salt = os.urandom(16)

    # 3. Derivar dos claves de 32 bytes: una para cifrado, otra para HMAC
    # Total: 64 bytes (256 bits cifrado + 256 bits HMAC)
    master_key = derive_key_from_password(password, salt, length=64)
    encryption_key = master_key[:32]  # Primera mitad para AES
    hmac_key = master_key[32:]  # Segunda mitad para HMAC

    # 4. Generar IV aleatorio para AES-CBC
    iv = os.urandom(16)

    # 5. Cifrar con AES-256-CBC
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Aplicar padding PKCS7 manualmente
    plaintext = private_pem
    padding_length = 16 - (len(plaintext) % 16)
    padded_plaintext = plaintext + bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # 6. Calcular HMAC sobre (salt + iv + ciphertext)
    hmac_data = salt + iv + ciphertext
    hmac_tag = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()

    return {
        'salt': salt,
        'iv': iv,
        'ciphertext': ciphertext,
        'hmac': hmac_tag
    }


def decrypt_private_key(encrypted_data: dict, password: str):
    """
    Descifra una clave privada RSA cifrada con AES-256-CBC.

    Args:
        encrypted_data: dict con salt, iv, ciphertext, hmac
        password: Contraseña del usuario

    Returns:
        Objeto clave privada RSA

    Raises:
        ValueError: Si el HMAC no coincide (datos manipulados)
        ValueError: Si la contraseña es incorrecta
    """
    salt = encrypted_data['salt']
    iv = encrypted_data['iv']
    ciphertext = encrypted_data['ciphertext']
    stored_hmac = encrypted_data['hmac']

    # 1. Derivar las claves (igual que en cifrado)
    master_key = derive_key_from_password(password, salt, length=64)
    encryption_key = master_key[:32]
    hmac_key = master_key[32:]

    # 2. Verificar HMAC (CRÍTICO: hacerlo ANTES de descifrar)
    hmac_data = salt + iv + ciphertext
    calculated_hmac = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()

    if not hmac.compare_digest(calculated_hmac, stored_hmac):
        raise ValueError("HMAC inválido: los datos han sido manipulados o la contraseña es incorrecta")

    # 3. Descifrar con AES-256-CBC
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # 4. Quitar padding PKCS7
    padding_length = padded_plaintext[-1]
    private_pem = padded_plaintext[:-padding_length]

    # 5. Cargar la clave privada desde PEM
    try:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,  # Ya está descifrada
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Error al cargar la clave privada: {e}")


# ==============================
#  FUNCIONES DE ALMACENAMIENTO
# ==============================
def save_encrypted_private_key(private_key, password: str, username: str,
                               storage_path: str = None) -> bytes:
    """
    Cifra y guarda una clave privada en formato compacto para BD o archivo.

    Args:
        private_key: Objeto clave privada RSA
        password: Contraseña del usuario
        username: Nombre del usuario (para logs)
        storage_path: Ruta opcional para guardar en archivo

    Returns:
        bytes: Formato compacto (salt + iv + hmac + ciphertext)
    """
    encrypted_data = encrypt_private_key(private_key, password)

    # Formato compacto: concatenar todo en un solo blob
    # [salt:16][iv:16][hmac:32][ciphertext:variable]
    blob = (
            encrypted_data['salt'] +
            encrypted_data['iv'] +
            encrypted_data['hmac'] +
            encrypted_data['ciphertext']
    )

    # Opcional: guardar en archivo
    if storage_path:
        os.makedirs(os.path.dirname(storage_path), exist_ok=True)
        with open(storage_path, 'wb') as f:
            f.write(blob)
        print(f"[KEYSTORE] Clave privada de '{username}' guardada en {storage_path}")

    return blob


def load_encrypted_private_key(blob: bytes, password: str):
    """
    Carga y descifra una clave privada desde formato compacto.

    Args:
        blob: bytes en formato [salt:16][iv:16][hmac:32][ciphertext:*]
        password: Contraseña del usuario

    Returns:
        Objeto clave privada RSA
    """
    # Parsear el blob
    if len(blob) < 64:  # 16 + 16 + 32 = 64 bytes mínimos
        raise ValueError("Blob de clave privada corrupto (muy corto)")

    salt = blob[0:16]
    iv = blob[16:32]
    hmac_tag = blob[32:64]
    ciphertext = blob[64:]

    encrypted_data = {
        'salt': salt,
        'iv': iv,
        'hmac': hmac_tag,
        'ciphertext': ciphertext
    }

    return decrypt_private_key(encrypted_data, password)


# ==============================
#  UTILIDADES
# ==============================
def change_private_key_password(blob: bytes, old_password: str,
                                new_password: str) -> bytes:
    """
    Cambia la contraseña de una clave privada cifrada.

    Args:
        blob: Clave privada cifrada (formato compacto)
        old_password: Contraseña actual
        new_password: Nueva contraseña

    Returns:
        Nuevo blob cifrado con la nueva contraseña
    """
    # 1. Descifrar con la contraseña antigua
    private_key = load_encrypted_private_key(blob, old_password)

    # 2. Re-cifrar con la contraseña nueva
    encrypted_data = encrypt_private_key(private_key, new_password)

    # 3. Crear nuevo blob
    new_blob = (
            encrypted_data['salt'] +
            encrypted_data['iv'] +
            encrypted_data['hmac'] +
            encrypted_data['ciphertext']
    )

    return new_blob