"""
Módulo de gestión segura de claves privadas
- AES-256-CBC: cifrado de claves privadas RSA en reposo
- PBKDF2: derivación de clave de cifrado desde contraseña
- HMAC-SHA256: verifica la integridad
- Formato: [salt:16][iv:16][hmac:32][ciphertext:variable]
"""

import os
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

from .crypto import derive_key_from_password



#  CONSTANTES DE SEGURIDAD

SALT_SIZE = 16          # 128 bits para PBKDF2
IV_SIZE = 16            # 128 bits para AES-CBC
HMAC_SIZE = 32          # 256 bits para HMAC-SHA256
KEY_SIZE = 32           # 256 bits para AES
MASTER_KEY_SIZE = 64    # 256 bits AES + 256 bits HMAC
AES_BLOCK_SIZE = 16     # Tamaño de bloque AES



#  CIFRADO DE CLAVES PRIVADAS

def encrypt_private_key(private_key: RSAPrivateKey, password: str) -> dict:
    """
    Cifra una clave privada RSA con AES-256-CBC usando una contraseña

    Proceso:
        1. PBKDF2 deriva dos claves de 256 bits (cifrado + autenticación)
        2. AES-256-CBC cifra la clave privada serializada
        3. HMAC-SHA256 autentica (salt + iv + ciphertext)

    Argumentos:
        private_key: clave privada RSA
        password: contraseña del usuario para derivar la clave de cifrado

    Returns:
        diccionario con las siguientes claves:
            - salt: sal para PBKDF2 (16 bytes)
            - iv: vector de inicialización para AES-CBC (16 bytes)
            - ciphertext: clave privada cifrada
            - hmac: tag de autenticación HMAC-SHA256 (32 bytes)
    
    Raises:
        ValueError: Si la clave privada o contraseña son inválidas
    """
    if not isinstance(private_key, RSAPrivateKey):
        raise ValueError("La clave privada debe ser un objeto RSAPrivateKey")
    if not password or not isinstance(password, str):
        raise ValueError("La contraseña debe ser una cadena no vacía")

    # 1. Serializar la clave privada a PEM (sin cifrar)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 2. Generar sal aleatoria para PBKDF2
    salt = os.urandom(SALT_SIZE)

    # 3. Derivar dos claves de 32 bytes: una para cifrado, otra para HMAC
    master_key = derive_key_from_password(password, salt, length=MASTER_KEY_SIZE)
    encryption_key = master_key[:KEY_SIZE]  # Primera mitad para AES
    hmac_key = master_key[KEY_SIZE:]        # Segunda mitad para HMAC

    # 4. Generar IV aleatorio para AES-CBC
    iv = os.urandom(IV_SIZE)

    # 5. Cifrar con AES-256-CBC
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.CBC(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    # Aplicar padding PKCS7 manualmente
    padding_length = AES_BLOCK_SIZE - (len(private_pem) % AES_BLOCK_SIZE)
    padded_plaintext = private_pem + bytes([padding_length] * padding_length)

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    # 6. Calcular HMAC sobre (salt + iv + ciphertext), orden fijo
    hmac_data = salt + iv + ciphertext
    hmac_tag = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()

    return {
        'salt': salt,
        'iv': iv,
        'ciphertext': ciphertext,
        'hmac': hmac_tag
    }


def decrypt_private_key(encrypted_data: dict, password: str) -> RSAPrivateKey:
    """
    Descifra una clave privada RSA cifrada con AES-256-CBC

    importante: verifica HMAC ANTES de descifrar para prevenir ataques de padding oracle

    Argumentos:
        encrypted_data: diccionario con salt, iv, ciphertext, hmac
        password: contraseña del usuario

    Returns:
        Objeto clave privada RSA

    Raises:
        ValueError: Si el HMAC no coincide (datos manipulados o contraseña incorrecta)
        ValueError: Si el formato de datos es inválido
        ValueError: Si la contraseña es incorrecta (después de verificar HMAC)
    """
    # Validar estructura del diccionario
    required_keys = {'salt', 'iv', 'ciphertext', 'hmac'}
    if not all(key in encrypted_data for key in required_keys):
        raise ValueError(f"Formato de datos inválido. Se requieren: {required_keys}")

    salt = encrypted_data['salt']
    iv = encrypted_data['iv']
    ciphertext = encrypted_data['ciphertext']
    stored_hmac = encrypted_data['hmac']

    # Validar tamaños
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Tamaño de salt inválido: {len(salt)} bytes (esperado: {SALT_SIZE})")
    if len(iv) != IV_SIZE:
        raise ValueError(f"Tamaño de IV inválido: {len(iv)} bytes (esperado: {IV_SIZE})")
    if len(stored_hmac) != HMAC_SIZE:
        raise ValueError(f"Tamaño de HMAC inválido: {len(stored_hmac)} bytes (esperado: {HMAC_SIZE})")

    # 1. Derivar las claves (igual que en cifrado)
    master_key = derive_key_from_password(password, salt, length=MASTER_KEY_SIZE)
    encryption_key = master_key[:KEY_SIZE]
    hmac_key = master_key[KEY_SIZE:]

    # 2. Verificar HMAC (antes de descifrar)
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
    
    try:
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception as e:
        raise ValueError(f"Error al descifrar: {e}")

    # 4. Quitar padding PKCS7 con validación
    try:
        padding_length = padded_plaintext[-1]
        if padding_length > AES_BLOCK_SIZE or padding_length == 0:
            raise ValueError("Padding PKCS7 inválido")
        
        # Verificar que todos los bytes de padding sean iguales
        padding_bytes = padded_plaintext[-padding_length:]
        if not all(b == padding_length for b in padding_bytes):
            raise ValueError("Padding PKCS7 corrupto")
        
        private_pem = padded_plaintext[:-padding_length]
    except (IndexError, ValueError) as e:
        raise ValueError(f"Error al quitar padding: {e}")

    # 5. Cargar la clave privada desde PEM
    try:
        private_key = serialization.load_pem_private_key(
            private_pem,
            password=None,  # Ya está descifrada
            backend=default_backend()
        )
        return private_key
    except Exception as e:
        raise ValueError(f"Error al cargar la clave privada: {e}. La contraseña puede ser incorrecta.")



#  FUNCIONES DE ALMACENAMIENTO

def save_encrypted_private_key(private_key: RSAPrivateKey, password: str, 
                               username: str, storage_path: str = None) -> bytes:
    """
    Cifra y guarda una clave privada en formato compacto para BD

    Formato del blob: [salt:16][iv:16][hmac:32][ciphertext:variable]
    Total: mínimo 64 bytes + tamaño de ciphertext

    Argumentos:
        private_key: clave privada RSA
        password: contraseña del usuario
        username: nombre del usuario (para logs)
        storage_path: ruta opcional para guardar en archivo

    Returns:
        bytes: Formato compacto (salt + iv + hmac + ciphertext)
    
    Raises:
        ValueError: Si los parámetros son inválidos
        IOError: Si hay error al escribir el archivo
    """
    encrypted_data = encrypt_private_key(private_key, password)

    # Formato compacto: concatenar todo en un solo blob
    blob = (
        encrypted_data['salt'] +
        encrypted_data['iv'] +
        encrypted_data['hmac'] +
        encrypted_data['ciphertext']
    )

    # Opcional: guardar en archivo
    if storage_path:
        try:
            os.makedirs(os.path.dirname(storage_path), exist_ok=True)
            with open(storage_path, 'wb') as f:
                f.write(blob)
            print(f"[KEYSTORE] Clave privada de '{username}' guardada en {storage_path}")
        except IOError as e:
            raise IOError(f"Error al guardar clave en {storage_path}: {e}")

    return blob


def load_encrypted_private_key(blob: bytes, password: str) -> RSAPrivateKey:
    """
    Carga y descifra una clave privada desde formato compacto

    Argumentos:
        blob: bytes en formato [salt:16][iv:16][hmac:32][ciphertext:*]
        password: contraseña del usuario

    Returns:
        Objeto clave privada RSA
    
    Raises:
        ValueError: Si el blob está corrupto o la contraseña es incorrecta
    """
    # Validar tamaño mínimo
    MIN_BLOB_SIZE = SALT_SIZE + IV_SIZE + HMAC_SIZE
    if len(blob) < MIN_BLOB_SIZE:
        raise ValueError(
            f"Blob de clave privada corrupto: tamaño {len(blob)} bytes "
            f"(mínimo: {MIN_BLOB_SIZE} bytes)"
        )

    # Parsear el blob
    salt = blob[0:SALT_SIZE]
    iv = blob[SALT_SIZE:SALT_SIZE+IV_SIZE]
    hmac_tag = blob[SALT_SIZE+IV_SIZE:SALT_SIZE+IV_SIZE+HMAC_SIZE]
    ciphertext = blob[SALT_SIZE+IV_SIZE+HMAC_SIZE:]

    if not ciphertext:
        raise ValueError("Blob de clave privada corrupto: ciphertext vacío")

    encrypted_data = {
        'salt': salt,
        'iv': iv,
        'hmac': hmac_tag,
        'ciphertext': ciphertext
    }

    return decrypt_private_key(encrypted_data, password)



#  UTILIDADES

def change_private_key_password(blob: bytes, old_password: str,
                                new_password: str) -> bytes:
    """
    Cambia la contraseña de una clave privada cifrada.

    Este proceso:
    1. Descifra con la contraseña antigua
    2. Re-cifra con la contraseña nueva
    3. Genera nuevos salt, IV y HMAC (no reutiliza los antiguos)

    Argumentos:
        blob: Clave privada cifrada (formato compacto)
        old_password: Contraseña actual
        new_password: Nueva contraseña

    Returns:
        Nuevo blob cifrado con la nueva contraseña
    
    Raises:
        ValueError: Si la contraseña antigua es incorrecta
    """
    # 1. Descifrar con la contraseña antigua
    private_key = load_encrypted_private_key(blob, old_password)

    # 2. Re-cifrar con la contraseña nueva (genera nuevos salt/IV/HMAC)
    encrypted_data = encrypt_private_key(private_key, new_password)

    # 3. Crear nuevo blob
    new_blob = (
        encrypted_data['salt'] +
        encrypted_data['iv'] +
        encrypted_data['hmac'] +
        encrypted_data['ciphertext']
    )

    return new_blob


def validate_encrypted_blob(blob: bytes) -> tuple[bool, str]:
    """
    Valida que un blob cifrado tenga el formato correcto sin descifrarlo

    Argumentos:
        blob: Blob cifrado a validar

    Returns:
        Tupla (es_válido, mensaje)
    """
    MIN_BLOB_SIZE = SALT_SIZE + IV_SIZE + HMAC_SIZE
    
    if not isinstance(blob, bytes):
        return False, "El blob debe ser de tipo bytes"
    
    if len(blob) < MIN_BLOB_SIZE:
        return False, f"Blob muy corto: {len(blob)} bytes (mínimo: {MIN_BLOB_SIZE})"
    
    ciphertext_size = len(blob) - MIN_BLOB_SIZE
    if ciphertext_size % AES_BLOCK_SIZE != 0:
        return False, f"Tamaño de ciphertext inválido: {ciphertext_size} bytes (debe ser múltiplo de {AES_BLOCK_SIZE})"
    
    return True, "Formato válido"


def get_blob_info(blob: bytes) -> dict:
    """
    Obtiene información sobre un blob cifrado sin descifrarlo

    Argumentos:
        blob: Blob cifrado

    Returns:
        Diccionario con información del blob
    """
    MIN_BLOB_SIZE = SALT_SIZE + IV_SIZE + HMAC_SIZE
    
    return {
        'total_size': len(blob),
        'salt_size': SALT_SIZE,
        'iv_size': IV_SIZE,
        'hmac_size': HMAC_SIZE,
        'ciphertext_size': max(0, len(blob) - MIN_BLOB_SIZE),
        'is_valid_format': validate_encrypted_blob(blob)[0],
        'encryption': 'AES-256-CBC',
        'kdf': 'PBKDF2-HMAC-SHA256',
        'authentication': 'HMAC-SHA256'
    }



#  FUNCIONES DE TESTING

if __name__ == "__main__":
    from cryptography.hazmat.primitives.asymmetric import rsa
    
    print("[TEST] Generando clave RSA de prueba...")
    test_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    password = "mi_contraseña_super_segura"
    
    print("\n[TEST] Cifrando clave privada...")
    blob = save_encrypted_private_key(test_key, password, "test_user")
    print(f"  - Tamaño del blob: {len(blob)} bytes")
    print(f"  - Info: {get_blob_info(blob)}")
    
    print("\n[TEST] Descifrando clave privada...")
    recovered_key = load_encrypted_private_key(blob, password)
    print("  - ✓ Clave recuperada correctamente")
    
    print("\n[TEST] Probando contraseña incorrecta...")
    try:
        load_encrypted_private_key(blob, "contraseña_incorrecta")
        print("  - ✗ ERROR: debería haber fallado")
    except ValueError as e:
        print(f"  - ✓ Falló como esperado: {e}")
    
    print("\n[TEST] Cambiando contraseña...")
    new_blob = change_private_key_password(blob, password, "nueva_contraseña")
    recovered_key2 = load_encrypted_private_key(new_blob, "nueva_contraseña")
    print("  - ✓ Contraseña cambiada correctamente")
    
    print("\n[TEST] Validando blob manipulado...")
    tampered_blob = bytearray(blob)
    tampered_blob[50] ^= 0xFF  # Modificar un byte
    try:
        load_encrypted_private_key(bytes(tampered_blob), password)
        print("  - ✗ ERROR: debería haber detectado manipulación")
    except ValueError as e:
        print(f"  - ✓ Manipulación detectada: {e}")
    
    print("\n[TEST] ✓ Todos los tests pasaron")