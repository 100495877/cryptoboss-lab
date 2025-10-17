from chat_seguro.core.crypto import *

# 1. Cifrar un mensaje
mensaje = "Hola, esto es secreto!"
ciphertext, key, nonce, tag = encrypt_message_aes_gcm(mensaje)
print(f" Mensaje cifrado: {ciphertext[:20]}...")

# 2. Descifrar el mensaje
mensaje_descifrado = decrypt_message_aes_gcm(ciphertext, key, nonce, tag)
print(f" Mensaje descifrado: {mensaje_descifrado}")

# 3. Generar claves RSA
priv, pub = generate_rsa_keypair()
print(" Claves RSA generadas")

# 4. Cifrar la clave de sesión con RSA
key_cifrada = encrypt_session_key_rsa_oaep(key, pub)
print(f" Clave cifrada con RSA: {len(key_cifrada)} bytes")

# 5. Descifrar la clave de sesión
key_recuperada = decrypt_session_key_rsa_oaep(key_cifrada, priv)
print(f" Clave recuperada correctamente: {key == key_recuperada}")


#para pasar el test escribe en la terminal: python test_crypto_simple.py