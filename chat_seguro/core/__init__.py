
"""
Módulo core con funcionalidades criptográficas.

Módulos disponibles:
- auth: Autenticación de usuarios (hashing de contraseñas)
- crypto: Cifrado simétrico/asimétrico (AES-GCM, RSA-OAEP)
- sign: Firma digital (RSA-PSS)
- keystore: Gestión segura de claves privadas (AES-CBC + PBKDF2)
- pki: Infraestructura de clave pública (CA, certificados X.509)
"""

# Importar módulos para facilitar el uso
from . import auth
from . import crypto
from . import sign
from . import keystore
from . import pki

__all__ = ['auth', 'crypto', 'sign', 'keystore', 'pki']
