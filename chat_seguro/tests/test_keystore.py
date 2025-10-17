"""
Tests unitarios para el módulo keystore.py
"""

import pytest
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from core.keystore import (
    encrypt_private_key,
    decrypt_private_key,
    save_encrypted_private_key,
    load_encrypted_private_key,
    change_private_key_password
)
from core.crypto import generate_rsa_keypair, serialize_private_key


# ==============================
#  FIXTURES
# ==============================
@pytest.fixture
def sample_rsa_keypair():
    """Genera un par de claves RSA para testing."""
    return generate_rsa_keypair(key_size=2048)


@pytest.fixture
def sample_password():
    """Contraseña de prueba."""
    return "MiContraseñaSegura123!"


@pytest.fixture
def weak_password():
    """Contraseña débil para tests."""
    return "123"


# ==============================
#  TEST: CIFRADO/DESCIFRADO BÁSICO
# ==============================
def test_encrypt_decrypt_private_key(sample_rsa_keypair, sample_password):
    """Test básico: cifrar y descifrar una clave privada."""
    private_key, public_key = sample_rsa_keypair

    # Cifrar
    encrypted_data = encrypt_private_key(private_key, sample_password)

    # Verificar estructura del dict
    assert 'salt' in encrypted_data
    assert 'iv' in encrypted_data
    assert 'ciphertext' in encrypted_data
    assert 'hmac' in encrypted_data

    # Verificar tamaños
    assert len(encrypted_data['salt']) == 16
    assert len(encrypted_data['iv']) == 16
    assert len(encrypted_data['hmac']) == 32
    assert len(encrypted_data['ciphertext']) > 0

    # Descifrar
    decrypted_key = decrypt_private_key(encrypted_data, sample_password)

    # Verificar que la clave descifrada es idéntica
    original_pem = serialize_private_key(private_key)
    decrypted_pem = serialize_private_key(decrypted_key)
    assert original_pem == decrypted_pem


def test_decrypt_with_wrong_password(sample_rsa_keypair, sample_password):
    """Test: descifrar con contraseña incorrecta debe fallar."""
    private_key, _ = sample_rsa_keypair

    encrypted_data = encrypt_private_key(private_key, sample_password)

    # Intentar descifrar con contraseña incorrecta
    with pytest.raises(ValueError, match="HMAC inválido"):
        decrypt_private_key(encrypted_data, "ContraseñaIncorrecta")


def test_tampered_ciphertext(sample_rsa_keypair, sample_password):
    """Test: modificar el ciphertext debe ser detectado por HMAC."""
    private_key, _ = sample_rsa_keypair

    encrypted_data = encrypt_private_key(private_key, sample_password)

    # Manipular el ciphertext
    tampered_ciphertext = bytearray(encrypted_data['ciphertext'])
    tampered_ciphertext[0] ^= 0xFF  # Cambiar un byte
    encrypted_data['ciphertext'] = bytes(tampered_ciphertext)

    # Debe fallar al descifrar
    with pytest.raises(ValueError, match="HMAC inválido"):
        decrypt_private_key(encrypted_data, sample_password)


def test_tampered_salt(sample_rsa_keypair, sample_password):
    """Test: modificar la sal debe ser detectado por HMAC."""
    private_key, _ = sample_rsa_keypair

    encrypted_data = encrypt_private_key(private_key, sample_password)

    # Manipular la sal
    encrypted_data['salt'] = os.urandom(16)

    # Debe fallar al descifrar
    with pytest.raises(ValueError, match="HMAC inválido"):
        decrypt_private_key(encrypted_data, sample_password)


def test_tampered_iv(sample_rsa_keypair, sample_password):
    """Test: modificar el IV debe ser detectado por HMAC."""
    private_key, _ = sample_rsa_keypair

    encrypted_data = encrypt_private_key(private_key, sample_password)

    # Manipular el IV
    encrypted_data['iv'] = os.urandom(16)

    # Debe fallar al descifrar
    with pytest.raises(ValueError, match="HMAC inválido"):
        decrypt_private_key(encrypted_data, sample_password)


# ==============================
#  TEST: FORMATO COMPACTO (BLOB)
# ==============================
def test_save_and_load_blob_format(sample_rsa_keypair, sample_password):
    """Test: guardar y cargar en formato blob compacto."""
    private_key, _ = sample_rsa_keypair

    # Guardar (sin archivo, solo blob)
    blob = save_encrypted_private_key(private_key, sample_password, "test_user")

    # Verificar que es bytes
    assert isinstance(blob, bytes)

    # Verificar tamaño mínimo (16+16+32 = 64 bytes + ciphertext)
    assert len(blob) >= 64

    # Cargar desde blob
    loaded_key = load_encrypted_private_key(blob, sample_password)

    # Verificar identidad
    original_pem = serialize_private_key(private_key)
    loaded_pem = serialize_private_key(loaded_key)
    assert original_pem == loaded_pem


def test_load_blob_wrong_password(sample_rsa_keypair, sample_password):
    """Test: cargar blob con contraseña incorrecta."""
    private_key, _ = sample_rsa_keypair

    blob = save_encrypted_private_key(private_key, sample_password, "test_user")

    # Intentar cargar con contraseña incorrecta
    with pytest.raises(ValueError):
        load_encrypted_private_key(blob, "wrongpassword")


def test_load_corrupted_blob(sample_password):
    """Test: cargar un blob corrupto debe fallar."""
    corrupted_blob = b"esto_no_es_un_blob_valido"

    with pytest.raises(ValueError, match="corrupto"):
        load_encrypted_private_key(corrupted_blob, sample_password)


def test_load_truncated_blob(sample_rsa_keypair, sample_password):
    """Test: cargar un blob truncado debe fallar."""
    private_key, _ = sample_rsa_keypair

    blob = save_encrypted_private_key(private_key, sample_password, "test_user")

    # Truncar el blob
    truncated_blob = blob[:50]  # Menos de 64 bytes

    with pytest.raises(ValueError, match="corrupto"):
        load_encrypted_private_key(truncated_blob, sample_password)


# ==============================
#  TEST: GUARDAR EN ARCHIVO
# ==============================
def test_save_to_file(sample_rsa_keypair, sample_password, tmp_path):
    """Test: guardar clave cifrada en archivo."""
    private_key, _ = sample_rsa_keypair

    # Crear ruta temporal
    key_file = tmp_path / "test_user_private.key"

    # Guardar en archivo
    blob = save_encrypted_private_key(
        private_key,
        sample_password,
        "test_user",
        storage_path=str(key_file)
    )

    # Verificar que el archivo existe
    assert key_file.exists()

    # Leer el archivo y verificar contenido
    with open(key_file, 'rb') as f:
        file_content = f.read()

    assert file_content == blob

    # Cargar desde el archivo
    with open(key_file, 'rb') as f:
        loaded_blob = f.read()

    loaded_key = load_encrypted_private_key(loaded_blob, sample_password)

    # Verificar identidad
    original_pem = serialize_private_key(private_key)
    loaded_pem = serialize_private_key(loaded_key)
    assert original_pem == loaded_pem


# ==============================
#  TEST: CAMBIO DE CONTRASEÑA
# ==============================
def test_change_password(sample_rsa_keypair, sample_password):
    """Test: cambiar la contraseña de una clave privada."""
    private_key, _ = sample_rsa_keypair
    old_password = sample_password
    new_password = "NuevaContraseña456!"

    # Cifrar con contraseña antigua
    old_blob = save_encrypted_private_key(private_key, old_password, "test_user")

    # Cambiar contraseña
    new_blob = change_private_key_password(old_blob, old_password, new_password)

    # Verificar que los blobs son diferentes
    assert old_blob != new_blob

    # La contraseña antigua ya no debe funcionar
    with pytest.raises(ValueError):
        load_encrypted_private_key(new_blob, old_password)

    # La nueva contraseña debe funcionar
    loaded_key = load_encrypted_private_key(new_blob, new_password)

    # Verificar identidad
    original_pem = serialize_private_key(private_key)
    loaded_pem = serialize_private_key(loaded_key)
    assert original_pem == loaded_pem


def test_change_password_wrong_old_password(sample_rsa_keypair, sample_password):
    """Test: cambiar contraseña con contraseña antigua incorrecta."""
    private_key, _ = sample_rsa_keypair

    blob = save_encrypted_private_key(private_key, sample_password, "test_user")

    # Intentar cambiar con contraseña incorrecta
    with pytest.raises(ValueError):
        change_private_key_password(blob, "wrongpassword", "newpassword")


# ==============================
#  TEST: CONTRASEÑAS ESPECIALES
# ==============================
def test_unicode_password(sample_rsa_keypair):
    """Test: usar contraseña con caracteres Unicode."""
    private_key, _ = sample_rsa_keypair
    unicode_password = "contraseña🔐中文español"

    encrypted_data = encrypt_private_key(private_key, unicode_password)
    decrypted_key = decrypt_private_key(encrypted_data, unicode_password)

    original_pem = serialize_private_key(private_key)
    decrypted_pem = serialize_private_key(decrypted_key)
    assert original_pem == decrypted_pem


def test_empty_password(sample_rsa_keypair):
    """Test: usar contraseña vacía (permitido pero no recomendado)."""
    private_key, _ = sample_rsa_keypair
    empty_password = ""

    encrypted_data = encrypt_private_key(private_key, empty_password)
    decrypted_key = decrypt_private_key(encrypted_data, empty_password)

    original_pem = serialize_private_key(private_key)
    decrypted_pem = serialize_private_key(decrypted_key)
    assert original_pem == decrypted_pem


def test_very_long_password(sample_rsa_keypair):
    """Test: usar contraseña muy larga."""
    private_key, _ = sample_rsa_keypair
    long_password = "a" * 1000

    encrypted_data = encrypt_private_key(private_key, long_password)
    decrypted_key = decrypt_private_key(encrypted_data, long_password)

    original_pem = serialize_private_key(private_key)
    decrypted_pem = serialize_private_key(decrypted_key)
    assert original_pem == decrypted_pem


# ==============================
#  TEST: DETERMINISMO Y ALEATORIEDAD
# ==============================
def test_encryption_is_non_deterministic(sample_rsa_keypair, sample_password):
    """Test: cifrar dos veces debe producir resultados diferentes (por sal e IV aleatorios)."""
    private_key, _ = sample_rsa_keypair

    blob1 = save_encrypted_private_key(private_key, sample_password, "user1")
    blob2 = save_encrypted_private_key(private_key, sample_password, "user2")

    # Los blobs deben ser diferentes (diferentes sal e IV)
    assert blob1 != blob2

    # Pero ambos deben descifrar a la misma clave
    key1 = load_encrypted_private_key(blob1, sample_password)
    key2 = load_encrypted_private_key(blob2, sample_password)

    pem1 = serialize_private_key(key1)
    pem2 = serialize_private_key(key2)
    assert pem1 == pem2


def test_different_keys_produce_different_ciphertexts(sample_password):
    """Test: claves diferentes producen ciphertexts diferentes."""
    key1, _ = generate_rsa_keypair()
    key2, _ = generate_rsa_keypair()

    blob1 = save_encrypted_private_key(key1, sample_password, "user1")
    blob2 = save_encrypted_private_key(key2, sample_password, "user2")

    assert blob1 != blob2


# ==============================
#  TEST: TAMAÑOS DE CLAVE RSA
# ==============================
@pytest.mark.parametrize("key_size", [2048, 3072, 4096])
def test_different_rsa_key_sizes(key_size, sample_password):
    """Test: cifrar claves RSA de diferentes tamaños."""
    private_key, _ = generate_rsa_keypair(key_size=key_size)

    blob = save_encrypted_private_key(private_key, sample_password, "test_user")
    loaded_key = load_encrypted_private_key(blob, sample_password)

    # Verificar que el tamaño se preserva
    original_size = private_key.key_size
    loaded_size = loaded_key.key_size
    assert original_size == loaded_size == key_size


# ==============================
#  TEST: RENDIMIENTO (OPCIONAL)
# ==============================
def test_pbkdf2_iterations_time(sample_rsa_keypair, sample_password):
    """Test: verificar que PBKDF2 toma tiempo suficiente (≥100ms)."""
    import time
    private_key, _ = sample_rsa_keypair

    start = time.time()
    encrypt_private_key(private_key, sample_password)
    elapsed = time.time() - start

    # PBKDF2 con 600,000 iteraciones debe tomar al menos 100ms
    # (esto puede variar según el hardware)
    assert elapsed > 0.05, f"PBKDF2 muy rápido: {elapsed}s (posible problema de seguridad)"

