from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography import x509
import cryptography.exceptions
from cryptography.x509.oid import NameOID
import os

PASSPHRASE = "Grupo_18"  # Esta clave no deberia de estar en claro en el codigo

"""COSAS QUE DISCUTIR:
    - Les parece bien agregar fecha de caducidad de compartir y/o opcion de dejar de compartir inmediatamente?
    - La password tiene que ser la del administrador de sistema?
    """

"""Esto se tiene que hacer al registrar a cada usuario"""


def generate_RSA_keys(user):
    RSA_keys = [None, None]
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    path_private_key = "./RSA_keys/PRK_" + str(user) + ".pem"
    with open(path_private_key, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(PASSPHRASE.encode()),
        ))

    generate_CSR(user)
    generate_public_key_certificate(user)


"Ahora generamos el CSR"


def generate_CSR(user):
    private_key = load_private_key(user, 1)
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        # Provide various details about who we are.
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MADRID"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"LEGANES"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"UC3M"),
        x509.NameAttribute(NameOID.COMMON_NAME, str(user)),
    ])).sign(private_key, hashes.SHA256())

    path = "./AC/solicitudes/csr_" + str(user) + ".pem"
    with open(path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))


"""Ahora tenemos que generar el certificado de clave PUBLICA"""


def generate_public_key_certificate(user):
    request = "csr_" + str(user) + ".pem"
    #print(request)
    os.chdir("./AC")
    # os.system("openssl ca -in ./solicitudes/" + request + " -notext -config ./openssl_AC.cnf").
    os.system("openssl ca -batch -passin pass:" + PASSPHRASE + " -in ./solicitudes/" + request + " -notext -config ./openssl_AC.cnf")
    """
    time.sleep(0.2)
    os.system("<< ")

    os.write(0, "y")
    os.write(0, "y")
    """
    serial = load_serial_certificate()
    #print("Serial num: " + serial)
    command = "copy .\\nuevoscerts\\" + serial + ".pem " + " ..\RSA_keys\PBKC_" + user + ".pem"
    #print(command)

    os.system(command)
    os.chdir("..")


def load_serial_certificate():
    path_txt = "./serial.old"
    with open(path_txt, 'r') as file:
        return file.readline().rstrip('\n')


"Esta funcion nos sirve para cargar de un fichero cifrado la clave privada de un usuario"


def load_private_key(user, csr=0):
    PEM_path = "./RSA_keys/PRK_" + str(user) + ".pem"

    with open(PEM_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=PASSPHRASE.encode(),
        )
    return private_key



"""Este modulo es el que usariamos para encriptar los usuarios y contraseñas de los usuario externos que quermemos
 compartir, al compartir deberiamos de fijar una fecha y ya cuando se caduca esa fecha se elimina del almacenamiento
 de claves del otro usuario dicha clave"""


def asymetric_encrypt(user_information, public_key):
    encrypted_info = []
    for information in user_information:
        ciphertext = public_key.encrypt(
            information.encode('iso8859-1'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_info.append(ciphertext)
    return encrypted_info


def asymetric_decrypt(encrypted_information, private_key):
    decrypted_info = []
    for ciphertext in encrypted_information:
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decrypted_info.append(plaintext.decode())
    return decrypted_info


"Este es el fichero que se le pasa al "


def create_text_file(content, path):
    file = open(path, "w+")
    for i in content:
        file.write(i)
        file.close()

def verify_cert_sign(AC_public_key, pem_data_to_check):
    try:
        issuer_public_key = AC_public_key
        cert_to_check = pem_data_to_check
        issuer_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert_to_check.signature_hash_algorithm,
        )
        return True
    except cryptography.exceptions.InvalidSignature:
        print("The signature of this certificate is not valid")
        return False

def load_AC_public_key():
    PEM_path = "./AC/ACCert.pem"
    with open(PEM_path, "rb") as key_file:
        cert = x509.load_pem_x509_certificate(
            key_file.read()
        )
    flag = verify_cert_sign(cert.public_key(), cert)
    public_key = cert.public_key()
    if flag:
        return public_key
    else:
        print("Error: Not valid certificate")


"Esta funcion nos sirve para cargar de un fichero pem la clave publica de un usuario"
def load_public_key(user):
    PEM_path = "./RSA_keys/PBKC_" + str(user) + ".pem"
    with open(PEM_path, "rb") as key_file:
        cert = x509.load_pem_x509_certificate(
            key_file.read()
        ) #este es el del usuario haria falta tambien el de AC1

    AC_public_key = load_AC_public_key()            # Cargamos la clave publica de la autoridad de certificacion
    flag = verify_cert_sign(AC_public_key, cert)    # Verificamos la firma del certificado correspondiente a la calve publica
    public_key = cert.public_key()
    if flag:
        return public_key
    else:
        print("Error: Not valid certificate")