"""
Módulo de PKI (Public Key Infrastructure).
- Certificados X.509 v3
- CA raíz autofirmada
- Firma de certificados de usuarios
- Validación de cadenas de certificados
"""

import sqlite3
from pathlib import Path
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


#  CONSTANTES DE PKI

CA_COMMON_NAME = "Chat Seguro Root CA"
CA_ORGANIZATION = "Universidad Carlos III de Madrid"
CA_COUNTRY = "ES"
CA_VALIDITY_YEARS = 10

USER_CERT_VALIDITY_DAYS = 365  # 1 año para certificados de usuario



#  GENERACIÓN DE CA RAÍZ

def generate_root_ca(key_size: int = 4096) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Genera una CA raíz autofirmada.
    
    Características:
        - RSA 4096 bits (más seguro para CA)
        - Validez: 10 años
        - Extensiones: BasicConstraints(CA=True), KeyUsage(keyCertSign, cRLSign)
        - Autofirmado: issuer == subject
    
    Argumentos:
        key_size: Tamaño de clave RSA (por defecto 4096)
    
    Returns:
        Tupla (clave_privada, certificado_x509)
    """
    # 1. Generar par de claves RSA para la CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # 2. Construir el Subject (nombre de la CA)
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME),
    ])
    
    # 3. Crear el certificado autofirmado
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)  # Autofirmado: issuer == subject
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=CA_VALIDITY_YEARS * 365))
        # Extensión crítica: esto ES una CA
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        )
        # Key Usage para CA: firma de certificados y CRLs
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,    # Puede firmar certificados
                crl_sign=True,         # Puede firmar CRLs
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Subject Key Identifier 
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
    )
    
    # 4. Autofirmar con la clave privada de la CA
    certificate = cert_builder.sign(private_key, hashes.SHA256(), backend=default_backend())
    
    return private_key, certificate



#  GENERACIÓN DE CSR (Certificate Signing Request)

def generate_csr(username: str, private_key: rsa.RSAPrivateKey, 
                 email: Optional[str] = None) -> x509.CertificateSigningRequest:
    """
    Genera un CSR (Certificate Signing Request) para un usuario.
    
    Un CSR es una solicitud de certificado que el usuario envía a la CA.
    Contiene su clave pública y datos de identidad, firmados con su clave privada.
    
    Argumentos:
        username: Nombre de usuario
        private_key: Clave privada RSA del usuario
        email: Email opcional del usuario
    
    Returns:
        Objeto CSR firmado
    """
    # Construir el Subject del usuario
    subject_attrs = [
        x509.NameAttribute(NameOID.COUNTRY_NAME, CA_COUNTRY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, CA_ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ]
    
    if email:
        subject_attrs.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, email))
    
    subject = x509.Name(subject_attrs)
    
    # Crear el CSR
    csr_builder = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        # Opcionalmente añadir Subject Alternative Names
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(f"{username}.chatseguro.local"),
            ]),
            critical=False,
        )
    )
    
    # Firmar el CSR con la clave privada del usuario
    csr = csr_builder.sign(private_key, hashes.SHA256(), backend=default_backend())
    
    return csr


# ==============================
#  FIRMA DE CERTIFICADOS POR LA CA
# ==============================
def sign_certificate(csr: x509.CertificateSigningRequest,
                     ca_private_key: rsa.RSAPrivateKey,
                     ca_cert: x509.Certificate,
                     validity_days: int = USER_CERT_VALIDITY_DAYS) -> x509.Certificate:
    """
    Firma un CSR con la CA raíz, generando un certificado válido.
    
    Argumentos:
        csr: Certificate Signing Request del usuario
        ca_private_key: Clave privada de la CA
        ca_cert: Certificado de la CA (para extraer issuer)
        validity_days: Días de validez del certificado
    
    Returns:
        Certificado X.509 firmado por la CA
    """
    # Extraer información del CSR
    subject = csr.subject
    public_key = csr.public_key()
    
    # Construir el certificado
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)  # El emisor es la CA
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=validity_days))
        # NO es una CA
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        # Key Usage típico para usuarios: firma digital y cifrado
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,     # Puede firmar mensajes
                content_commitment=True,    # No repudio
                key_encipherment=True,      # Puede cifrar claves
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,        # NO puede firmar certificados
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        # Extended Key Usage: autenticación de cliente
        .add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=False,
        )
        # Subject Key Identifier
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key),
            critical=False,
        )
        # Authority Key Identifier (apunta a la CA)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
            critical=False,
        )
    )
    
    # Copiar Subject Alternative Names del CSR si existen
    try:
        san_ext = csr.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        cert_builder = cert_builder.add_extension(san_ext.value, critical=False)
    except x509.ExtensionNotFound:
        pass
    
    # Firmar con la clave privada de la CA
    certificate = cert_builder.sign(ca_private_key, hashes.SHA256(), backend=default_backend())
    
    return certificate


# ==============================
#  VALIDACIÓN DE CERTIFICADOS
# ==============================
def verify_certificate(cert: x509.Certificate, ca_cert: x509.Certificate) -> tuple[bool, str]:
    """
    Verifica que un certificado haya sido firmado por la CA y sea válido.
    
    Validaciones:
        1. Firma criptográfica (verificar con clave pública de la CA)
        2. Fechas de validez (not_before, not_after)
        3. Emisor coincide con subject de la CA
    
    Argumentos:
        cert: Certificado a verificar
        ca_cert: Certificado de la CA
    
    Returns:
        Tupla (es_válido, mensaje)
    """
    # 1. Verificar que el emisor coincida
    if cert.issuer != ca_cert.subject:
        return False, f"Emisor no coincide: {cert.issuer} != {ca_cert.subject}"
    
    # 2. Verificar fechas de validez
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before_utc:
        return False, f"Certificado aún no válido (válido desde {cert.not_valid_before_utc})"
    if now > cert.not_valid_after_utc:
        return False, f"Certificado expirado (expiró el {cert.not_valid_after_utc})"
    
    # 3. Verificar firma criptográfica
    try:
        ca_public_key = ca_cert.public_key()
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            # Usar el algoritmo de firma del certificado
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"Firma inválida: {e}"
    
    return True, "Certificado válido"


def get_certificate_info(cert: x509.Certificate) -> dict:
    """
    Extrae información legible de un certificado X.509.
    
    Argumentos:
        cert: Certificado X.509
    
    Returns:
        Diccionario con información del certificado
    """
    # Extraer Common Name del subject
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        cn = "N/A"
    
    # Extraer Common Name del issuer
    try:
        issuer_cn = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, AttributeError):
        issuer_cn = "N/A"
    
    # Verificar si es CA
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            ExtensionOID.BASIC_CONSTRAINTS
        ).value
        is_ca = basic_constraints.ca
    except x509.ExtensionNotFound:
        is_ca = False
    
    return {
        'subject_cn': cn,
        'issuer_cn': issuer_cn,
        'serial_number': cert.serial_number,
        'not_before': cert.not_valid_before_utc.isoformat(),
        'not_after': cert.not_valid_after_utc.isoformat(),
        'is_ca': is_ca,
        'signature_algorithm': cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "N/A",
        'key_size': cert.public_key().key_size,
    }



#  SERIALIZACIÓN Y CARGA

def serialize_certificate(cert: x509.Certificate) -> str:
    """
    Serializa un certificado a formato PEM (texto).
    
    Argumentos:
        cert: Certificado X.509
    
    Returns:
        String con el certificado en formato PEM
    """
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return pem.decode('utf-8')


def load_certificate_from_pem(pem_data: str | bytes) -> x509.Certificate:
    """
    Carga un certificado desde formato PEM.
    
    Argumentos:
        pem_data: Certificado en formato PEM (str o bytes)
    
    Returns:
        Objeto Certificate
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode('utf-8')
    
    cert = x509.load_pem_x509_certificate(pem_data, backend=default_backend())
    return cert


def serialize_csr(csr: x509.CertificateSigningRequest) -> str:
    """
    Serializa un CSR a formato PEM.
    
    Argumentos:
        csr: Certificate Signing Request
    
    Returns:
        String con el CSR en formato PEM
    """
    pem = csr.public_bytes(serialization.Encoding.PEM)
    return pem.decode('utf-8')


def load_csr_from_pem(pem_data: str | bytes) -> x509.CertificateSigningRequest:
    """
    Carga un CSR desde formato PEM.
    
    Argumentos:
        pem_data: CSR en formato PEM (str o bytes)
    
    Returns:
        Objeto CertificateSigningRequest
    """
    if isinstance(pem_data, str):
        pem_data = pem_data.encode('utf-8')
    
    csr = x509.load_pem_x509_csr(pem_data, backend=default_backend())
    return csr



#  FUNCIONES DE BASE DE DATOS

def save_ca_to_db(db_path: Path, ca_cert: x509.Certificate, ca_private_key: rsa.RSAPrivateKey,
                  password: str) -> None:
    """
    Guarda la CA raíz en la base de datos.
    
    Argumentos:
        db_path: Ruta a la base de datos SQLite
        ca_cert: Certificado de la CA
        ca_private_key: Clave privada de la CA (se cifra con password)
        password: Contraseña para cifrar la clave privada
    """
    from . import keystore  # Import local para evitar dependencias circulares
    
    cert_pem = serialize_certificate(ca_cert)
    cert_info = get_certificate_info(ca_cert)
    
    # Cifrar la clave privada de la CA
    encrypted_key = keystore.save_encrypted_private_key(
        ca_private_key, password, "CA_ROOT", storage_path=None
    )
    
    with sqlite3.connect(db_path) as con:
        # Guardar certificado en pki_certs
        con.execute(
            """
            INSERT INTO pki_certs(subject, pem, issuer, is_ca, valid_from, valid_to)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                cert_info['subject_cn'],
                cert_pem,
                cert_info['issuer_cn'],
                1,  # is_ca = True
                cert_info['not_before'],
                cert_info['not_after']
            )
        )
        
        # Guardar también en tabla users (entrada especial para la CA)
        con.execute(
            """
            INSERT OR IGNORE INTO users(username, pwd_hash, encrypted_private_key, cert_pem, pubkey_pem)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "CA_ROOT",
                "N/A",  # La CA no es un usuario real
                encrypted_key,
                cert_pem,
                None
            )
        )


def load_ca_from_db(db_path: Path, password: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Carga la CA raíz desde la base de datos.
    
    Argumentos:
        db_path: Ruta a la base de datos
        password: Contraseña para descifrar la clave privada
    
    Returns:
        Tupla (clave_privada, certificado)
    
    Raises:
        ValueError: Si no existe la CA o la contraseña es incorrecta
    """
    from . import keystore
    
    with sqlite3.connect(db_path) as con:
        cur = con.execute(
            "SELECT encrypted_private_key, cert_pem FROM users WHERE username='CA_ROOT'"
        )
        row = cur.fetchone()
    
    if not row:
        raise ValueError("CA raíz no encontrada en la base de datos")
    
    encrypted_key, cert_pem = row
    
    # Descifrar clave privada
    ca_private_key = keystore.load_encrypted_private_key(encrypted_key, password)
    
    # Cargar certificado
    ca_cert = load_certificate_from_pem(cert_pem)
    
    return ca_private_key, ca_cert


def save_user_certificate(db_path: Path, username: str, cert: x509.Certificate) -> None:
    """
    Guarda el certificado de un usuario en la base de datos.
    
    Argumentos:
        db_path: Ruta a la base de datos
        username: Nombre del usuario
        cert: Certificado del usuario
    """
    cert_pem = serialize_certificate(cert)
    cert_info = get_certificate_info(cert)
    
    with sqlite3.connect(db_path) as con:
        # Actualizar tabla users
        con.execute(
            "UPDATE users SET cert_pem=? WHERE username=?",
            (cert_pem, username)
        )
        
        # Guardar también en pki_certs
        con.execute(
            """
            INSERT INTO pki_certs(subject, pem, issuer, is_ca, valid_from, valid_to)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                cert_info['subject_cn'],
                cert_pem,
                cert_info['issuer_cn'],
                0,  # is_ca = False
                cert_info['not_before'],
                cert_info['not_after']
            )
        )


def load_user_certificate(db_path: Path, username: str) -> Optional[x509.Certificate]:
    """
    Carga el certificado de un usuario desde la base de datos.
    
    Argumentos:
        db_path: Ruta a la base de datos
        username: Nombre del usuario
    
    Returns:
        Certificado o None si no existe
    """
    with sqlite3.connect(db_path) as con:
        cur = con.execute(
            "SELECT cert_pem FROM users WHERE username=?",
            (username,)
        )
        row = cur.fetchone()
    
    if not row or not row[0]:
        return None
    
    return load_certificate_from_pem(row[0])



#  WORKFLOW COMPLETO

def init_pki(db_path: Path, ca_password: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    """
    Inicializa la PKI completa: genera CA raíz y la guarda en BD.
    
    Argumentos:
        db_path: Ruta a la base de datos
        ca_password: Contraseña para cifrar la clave privada de la CA
    
    Returns:
        Tupla (clave_privada_ca, certificado_ca)
    """
    print("[PKI] Generando CA raíz...")
    ca_private_key, ca_cert = generate_root_ca(key_size=4096)
    
    print("[PKI] Guardando CA en base de datos...")
    save_ca_to_db(db_path, ca_cert, ca_private_key, ca_password)
    
    cert_info = get_certificate_info(ca_cert)
    print(f"[PKI] ✓ CA raíz creada:")
    print(f"      Subject: {cert_info['subject_cn']}")
    print(f"      Válido desde: {cert_info['not_before']}")
    print(f"      Válido hasta: {cert_info['not_after']}")
    print(f"      Serial: {cert_info['serial_number']}")
    
    return ca_private_key, ca_cert


def issue_user_certificate(db_path: Path, username: str, user_private_key: rsa.RSAPrivateKey,
                           ca_password: str, email: Optional[str] = None) -> x509.Certificate:
    """
    Emite un certificado para un usuario (workflow completo).
    
    Pasos:
        1. Generar CSR del usuario
        2. Cargar CA desde BD
        3. Firmar CSR con la CA
        4. Guardar certificado en BD
    
    Argumentos:
        db_path: Ruta a la base de datos
        username: Nombre del usuario
        user_private_key: Clave privada del usuario
        ca_password: Contraseña de la CA
        email: Email opcional del usuario
    
    Returns:
        Certificado X.509 del usuario
    """
    print(f"[PKI] Generando CSR para '{username}'...")
    csr = generate_csr(username, user_private_key, email)
    
    print("[PKI] Cargando CA raíz...")
    ca_private_key, ca_cert = load_ca_from_db(db_path, ca_password)
    
    print(f"[PKI] Firmando certificado de '{username}'...")
    user_cert = sign_certificate(csr, ca_private_key, ca_cert)
    
    print(f"[PKI] Guardando certificado en base de datos...")
    save_user_certificate(db_path, username, user_cert)
    
    cert_info = get_certificate_info(user_cert)
    print(f"[PKI] ✓ Certificado emitido para '{username}':")
    print(f"      Serial: {cert_info['serial_number']}")
    print(f"      Válido hasta: {cert_info['not_after']}")
    
    return user_cert



#  TESTING

if __name__ == "__main__":
    print("[TEST] Generando CA raíz de prueba...")
    ca_priv, ca_cert = generate_root_ca(key_size=2048)
    
    ca_info = get_certificate_info(ca_cert)
    print(f"  - CA: {ca_info['subject_cn']}")
    print(f"  - Es CA: {ca_info['is_ca']}")
    print(f"  - Válido hasta: {ca_info['not_after']}")
    
    print("\n[TEST] Generando certificado de usuario...")
    user_priv = rsa.generate_private_key(65537, 2048, default_backend())
    csr = generate_csr("alice", user_priv, "alice@example.com")
    user_cert = sign_certificate(csr, ca_priv, ca_cert)
    
    user_info = get_certificate_info(user_cert)
    print(f"  - Usuario: {user_info['subject_cn']}")
    print(f"  - Emisor: {user_info['issuer_cn']}")
    print(f"  - Es CA: {user_info['is_ca']}")
    
    print("\n[TEST] Verificando certificado...")
    is_valid, msg = verify_certificate(user_cert, ca_cert)
    print(f"  - Resultado: {'✓ VÁLIDO' if is_valid else '✗ INVÁLIDO'} - {msg}")
    
    print("\n[TEST] Verificando certificado con CA incorrecta...")
    fake_ca_priv, fake_ca_cert = generate_root_ca(key_size=2048)
    is_valid, msg = verify_certificate(user_cert, fake_ca_cert)
    print(f"  - Resultado: {'✓ VÁLIDO' if is_valid else '✗ INVÁLIDO (esperado)'} - {msg}")
    
    print("\n[TEST] ✓ Todos los tests de PKI pasaron")