"""
Módulo de firma digital para mensajes.
- RSA-PSS: firma digital con padding probabilístico
- SHA-256: función hash criptográfica
- Verificación de integridad y autenticidad
"""

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature
from typing import Optional



#  FIRMA DIGITAL (RSA-PSS)

def sign_message(private_key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    """
    Firma un mensaje con RSA-PSS (Probabilistic Signature Scheme)
    
    Argumentos:
        private_key: Clave privada RSA del firmante
        message: Datos a firmar (en bytes)
    
    Returns:
        Firma digital (bytes)
    
    Notas técnicas:
        - Algoritmo: RSA-PSS con SHA-256
        - MGF: MGF1 con SHA-256
        - Salt length: Máximo permitido (PSS.MAX_LENGTH)
        - Tamaño de firma: igual al tamaño de la clave RSA (ej: 384 bytes para RSA-3072)
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key: rsa.RSAPublicKey, message: bytes, 
                     signature: bytes) -> bool:
    """
    Verifica una firma digital RSA-PSS
    
    Argumentos:
        public_key: Clave pública RSA del firmante
        message: Datos originales que fueron firmados
        signature: Firma digital a verificar
    
    Returns:
        True si la firma es válida, False en caso contrario
    
    Notas:
        - Verifica tanto la autenticidad (quien firmó) como la integridad (no modificado)
        - NO lanza excepciones, devuelve False en caso de error
    """
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        # Captura cualquier otro error (clave inválida, formato incorrecto, etc.)
        return False



#  FUNCIONES DE ALTO NIVEL

def sign_message_package(private_key: rsa.RSAPrivateKey, nonce: bytes, 
                         ciphertext: bytes, tag: bytes) -> bytes:
    """
    Firma un paquete de mensaje completo (nonce + ciphertext + tag)
    
    Esta función es específica para el formato de mensajes del chat seguro,
    donde se firma la concatenación de los componentes del cifrado AES-GCM
    
    Argumentos:
        private_key: Clave privada RSA del emisor
        nonce: Nonce usado en AES-GCM (12 bytes)
        ciphertext: Mensaje cifrado
        tag: Tag de autenticación de AES-GCM (16 bytes)
    
    Returns:
        Firma digital del paquete completo
    """
    # Concatenar componentes en el orden correcto
    data_to_sign = nonce + ciphertext + tag
    return sign_message(private_key, data_to_sign)


def verify_message_package(public_key: rsa.RSAPublicKey, nonce: bytes,
                           ciphertext: bytes, tag: bytes, signature: bytes) -> bool:
    """
    Verifica la firma de un paquete de mensaje completo
    
    Argumentos:
        public_key: Clave pública RSA del emisor
        nonce: Nonce usado en AES-GCM
        ciphertext: Mensaje cifrado
        tag: Tag de autenticación de AES-GCM
        signature: Firma digital a verificar
    
    Returns:
        True si la firma es válida
    """
    data_to_verify = nonce + ciphertext + tag
    return verify_signature(public_key, data_to_verify, signature)


#  UTILIDADES

def get_signature_info(signature: bytes, key_size: int = 3072) -> dict:
    """
    Obtiene información sobre una firma digital
    
    Argumentos:
        signature: Firma digital
        key_size: Tamaño de la clave RSA en bits (para validar)
    
    Returns:
        Diccionario con información de la firma
    """
    expected_size = key_size // 8  # Tamaño en bytes
    
    return {
        'size_bytes': len(signature),
        'size_bits': len(signature) * 8,
        'expected_size_bytes': expected_size,
        'is_valid_size': len(signature) == expected_size,
        'algorithm': 'RSA-PSS',
        'hash_algorithm': 'SHA-256',
        'mgf': 'MGF1-SHA256'
    }


def format_signature_for_display(signature: bytes, max_length: int = 32) -> str:
    """
    Formatea una firma para mostrarla de forma legible
    
    Argumentos:
        signature: Firma digital
        max_length: Número máximo de bytes a mostrar (trunca si es mayor)
    
    Returns:
        Representación hexadecimal truncada
    """
    sig_hex = signature.hex()
    if len(sig_hex) > max_length * 2:
        return f"{sig_hex[:max_length*2]}... (total: {len(signature)} bytes)"
    return sig_hex


#  FUNCIONES DE VALIDACIÓN

def validate_signature_format(signature: bytes, key_size: int = 3072) -> tuple[bool, Optional[str]]:
    """
    Valida que una firma tenga el formato correcto antes de verificarla
    
    Argumentos:
        signature: Firma digital a validar
        key_size: Tamaño esperado de la clave RSA en bits
    
    Returns:
        Tupla (es_válida, mensaje_error)
    """
    expected_size = key_size // 8
    
    if not signature:
        return False, "La firma está vacía"
    
    if not isinstance(signature, bytes):
        return False, "La firma debe ser de tipo bytes"
    
    if len(signature) != expected_size:
        return False, f"Tamaño incorrecto: esperado {expected_size} bytes, recibido {len(signature)} bytes"
    
    return True, None
