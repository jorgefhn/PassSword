import os
import cryptography
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SymetricEncryptor:

    @staticmethod
    def symetric_encrypt(key, message):
        """Esta funcion encripta los mensaje que envia el usuario al servidor"""
        answer = [None, None, None]
        nonce = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        encryptor = cipher.encryptor()
        encripted_message = encryptor.update(message.encode()) + encryptor.finalize()
        ##Mover aqui el signature
        signature = HMAC.calculate_signature(key, encripted_message) #Aqui calculamos el signature del cifrado
        answer[0] = nonce
        answer[1] = encripted_message
        answer[2] = signature
        return answer

    @staticmethod
    def symetric_decrypt(key, message, nonce, signature):
        """Esta funcion desencripta los mensajes recividos desde el servidor"""
        HMAC.check_encripting_user(key, signature, message)  # Hacer al para que no devuelva el decrypted message
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
        decryptor = cipher.decryptor()
        decrypted_message = decryptor.update(message) + decryptor.finalize()
        return decrypted_message


class HMAC:

    @staticmethod
    def calculate_signature(key, uncripted_message):
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(uncripted_message.encode())  # Este es el mensaje antes de ser cifrado
        signature = h.finalize()              # Esto es lo que se deberia guardar junto al mensaje cifrado
        return signature                      # Tenemos que devolver la signature

    @staticmethod
    def check_encripting_user(key, signature, decrypted_message):
        """Esta funcion verifica que los mensajes recividos por el cliente son los mismos que el encripto"""
        h = hmac.HMAC(key, hashes.SHA256())
        try:
            h.update(decrypted_message)  # Este es el mensaje una vez descifrado
            h.verify(signature)          # Esta signaure es la que guardamos y la pasamos como parametrom
        except cryptography.exceptions.InvalidSignature:
            print("Error - Corrupt data")


class PasswordDerivation:
    @staticmethod
    def password_derivator(my_pass):
        """Funcion que se utiliza unica y exclusivamente cuando se crea un nuevo usuario en el sistema,
        devuelve en un array el salt y la clave derivada"""
        answer = [None, None]
        salt = os.urandom(16)
        # derive
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(my_pass.encode())
        answer[0] = salt
        answer[1] = key
        return answer

    @staticmethod
    def password_verification(salt, introduced_key, stored_key):
        """Funcion que verifica los datos de un usuario. El salt teine que ser almacenado en el json,
        la introduced_key es la que introduce el usuario por teclado y la stored_key es la que se obtiene del json"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        try:
            kdf.verify(introduced_key.encode(), stored_key)
            return True
        except cryptography.exceptions.InvalidKey:
            print("User information is not correct, try again!")
            return False