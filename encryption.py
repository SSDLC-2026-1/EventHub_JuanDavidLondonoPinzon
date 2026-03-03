"""
encryption.py

Laboratorio de Cifrado y Manejo de Credenciales

En este módulo deberás implementar:

- Descifrado AES (MODE_EAX)
- Hash de contraseña con salt usando PBKDF2-HMAC-SHA256
- Verificación de contraseña usando el mismo salt

NO modificar la función encrypt_aes().
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import hashlib
import os
import hmac

# ==========================================================
# AES-GCM (requiere pip install pycryptodome)
# ==========================================================

def encrypt_aes(texto, clave):
    """
    Cifra un texto usando AES en modo EAX.

    Retorna:
        texto_cifrado_hex
        nonce_hex
        tag_hex
    """

    texto_bytes = texto.encode()

    cipher = AES.new(clave, AES.MODE_EAX)

    nonce = cipher.nonce
    texto_cifrado, tag = cipher.encrypt_and_digest(texto_bytes)

    return (
        texto_cifrado.hex(),
        nonce.hex(),
        tag.hex()
    )




def decrypt_aes(texto_cifrado_hex, nonce_hex, tag_hex, clave):
    """
    Descifra texto cifrado con AES-EAX.

    Debes:

    1. Convertir texto_cifrado_hex, nonce_hex y tag_hex a bytes.
    2. Crear el objeto AES usando:
           AES.new(clave, AES.MODE_EAX, nonce=nonce)
    3. Usar decrypt_and_verify() para validar integridad.
    4. Retornar el texto descifrado como string.
    """

    # Convertir hex a bytes
    texto_cifrado = bytes.fromhex(texto_cifrado_hex)
    nonce = bytes.fromhex(nonce_hex)
    tag = bytes.fromhex(tag_hex)

    # Crear objeto AES con nonce
    cipher = AES.new(clave, AES.MODE_EAX, nonce=nonce)

    # Desencriptar y verificar integridad
    texto_descifrado = cipher.decrypt_and_verify(texto_cifrado, tag)

    # Convertir bytes a string y retornar
    return texto_descifrado.decode()

# ==========================================================
# PASSWORD HASHING (PBKDF2 - SHA256)
# ==========================================================


def hash_password(password):
    """
    Genera un hash seguro usando:

        PBKDF2-HMAC-SHA256

    Requisitos:

    - Generar salt aleatoria de 16 bytes.
    - Usar al menos 200000 iteraciones.
    - Derivar clave de 32 bytes.
    - Retornar un diccionario con:

        {
            "algorithm": "pbkdf2_sha256",
            "iterations": ...,
            "salt": salt_en_hex,
            "hash": hash_en_hex
        }

    Pista:
        hashlib.pbkdf2_hmac(...)
    """

    # Generar salt aleatoria de 16 bytes
    salt = get_random_bytes(16)
    
    # Configurar iteraciones
    iterations = 200000
    
    # Derivar clave usando PBKDF2-HMAC-SHA256
    hash_derivado = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    )
    
    # Retornar diccionario con salt y hash en formato hex
    return {
        "algorithm": "pbkdf2_sha256",
        "iterations": iterations,
        "salt": salt.hex(),
        "hash": hash_derivado.hex()
    }



def verify_password(password, stored_data):
    """
    Verifica una contraseña contra el hash almacenado.

    Debes:

    1. Extraer salt y iterations del diccionario.
    2. Convertir salt de hex a bytes.
    3. Recalcular el hash con la contraseña ingresada.
    4. Comparar usando hmac.compare_digest().
    5. Retornar True o False.

    stored_data tiene esta estructura:

        {
            "algorithm": "...",
            "iterations": ...,
            "salt": "...",
            "hash": "..."
        }
    """

    # Extraer salt e iterations del diccionario
    salt_hex = stored_data.get("salt")
    iterations = stored_data.get("iterations")
    hash_almacenado = stored_data.get("hash")
    
    # Convertir salt de hex a bytes
    salt = bytes.fromhex(salt_hex)
    
    # Recalcular el hash con la contraseña ingresada
    hash_recalculado = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt,
        iterations,
        dklen=32
    ).hex()
    
    # Comparar usando hmac.compare_digest() para evitar timing attacks
    return hmac.compare_digest(hash_recalculado, hash_almacenado)

def obfuscate_card_number(card_number):
    # Source - https://stackoverflow.com/q/9730653
    # Posted by Bill Swearingen
    # Retrieved 2026-03-03, License - CC BY-SA 3.0

    return card_number[-4:].rjust(len(card_number), "*")



if __name__ == "__main__":

    print("=== PRUEBA AES ===")

    texto = "Hola Mundo"
    clave = get_random_bytes(16)

    texto_cifrado, nonce, tag = encrypt_aes(texto, clave)

    print("Texto cifrado:", texto_cifrado)
    print("Nonce:", nonce)
    print("Tag:", tag)

    # Cuando implementen decrypt_aes, esto debe funcionar
    # texto_descifrado = decrypt_aes(texto_cifrado, nonce, tag, clave)
    # print("Texto descifrado:", texto_descifrado)


    print("\n=== PRUEBA HASH ===")

    password = "Password123!"

    # Cuando implementen hash_password:
    # pwd_data = hash_password(password)
    # print("Hash generado:", pwd_data)

    # Cuando implementen verify_password:
    # print("Verificación correcta:",
    #       verify_password("Password123!", pwd_data))

    print("\n=== PRUEBA ofuscación ===")
    card_number = "000000000000000000000"
    print("Número de tarjeta ofuscado:", obfuscate_card_number(card_number))