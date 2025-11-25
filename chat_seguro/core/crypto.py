"""
Módulo de cifrado simétrico y asimétrico para mensajes.
- AES-256-GCM: cifrado de mensajes (confidencialidad + integridad)
- RSA-OAEP: cifrado de la clave de sesión
- PBKDF2: derivación de claves a partir de contraseñas
"""
from __future__ import annotations
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend



#  DERIVACIÓN DE CLAVES (PBKDF2)
def derive_key_from_password(password: str, salt: bytes, length: int = 32) -> bytes:
    """
    Deriva una clave criptográfica a partir de una contraseña usando PBKDF2-HMAC-SHA256.

    Argumentos:
        password: Contraseña en texto plano
        salt: Sal criptográfica (debe ser única por usuario/clave)
        length: Longitud de la clave en bytes (32 = 256 bits por defecto)

    Returns:
        Clave derivada de 'length' bytes
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=600_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))


#  CIFRADO SIMÉTRICO (AES-GCM)
def encrypt_message_aes_gcm(plaintext: str) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Cifra un mensaje con AES-256-GCM.

    Argumentos:
        plaintext: Mensaje en texto plano

    Returns:
        Tupla de (ciphertext, key, nonce, tag)
    """
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return ciphertext, key, nonce, tag


def decrypt_message_aes_gcm(ciphertext: bytes, key: bytes, nonce: bytes, tag: bytes) -> str:
    """
    Descifra un mensaje cifrado con AES-256-GCM.
    """
    aesgcm = AESGCM(key)
    ciphertext_with_tag = ciphertext + tag
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=None)
    return plaintext_bytes.decode('utf-8')


#  CIFRADO ASIMÉTRICO (RSA-OAEP)
def generate_rsa_keypair(key_size: int = 2048) -> tuple:
    """
    Genera un par de claves RSA (privada y pública).
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def encrypt_session_key_rsa_oaep(session_key: bytes, public_key) -> bytes:
    """
    Cifra la clave de sesión AES con RSA-OAEP.
    """
    encrypted_key = public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def decrypt_session_key_rsa_oaep(encrypted_key: bytes, private_key) -> bytes:
    """
    Descifra la clave de sesión AES con RSA-OAEP.
    """
    session_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return session_key


#  SERIALIZACIÓN DE CLAVES
def serialize_private_key(private_key, password: str = None) -> bytes:
    """
    Convierte la clave privada RSA a formato PEM.
    """
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password.encode('utf-8'))

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )
    return pem


def serialize_public_key(public_key) -> bytes:
    """
    Convierte la clave pública RSA a formato PEM.
    """
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem


def load_private_key_from_pem(pem_data: bytes, password: str = None):
    """
    Carga una clave privada desde formato PEM.
    """
    pwd_bytes = password.encode('utf-8') if password else None
    private_key = serialization.load_pem_private_key(
        pem_data,
        password=pwd_bytes,
        backend=default_backend()
    )
    return private_key


def load_public_key_from_pem(pem_data: bytes):
    """
    Carga una clave pública desde formato PEM.
    """
    public_key = serialization.load_pem_public_key(
        pem_data,
        backend=default_backend()
    )
    return public_key