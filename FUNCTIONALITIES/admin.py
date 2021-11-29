
import time
import json
from cyber_security import SymetricEncryptor,HMAC,PasswordDerivation
from cyber_security2 import generate_RSA_keys
import base64

ANSI_RESET = "\u001B[0m";
ANSI_BLACK = "\u001B[30m";
ANSI_RED = "\u001B[31m";
ANSI_GREEN = "\u001B[32m";
ANSI_YELLOW = "\u001B[33m";
ANSI_BLUE = "\u001B[34m";
ANSI_PURPLE = "\u001B[35m";
ANSI_CYAN = "\u001B[36m";
ANSI_WHITE = "\u001B[37m";

class Admin:
    def __init__(self):
        self.users = self.recover_json_information("./JSONS/app_users.json")
        self.external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
        self.shared_accounts = self.recover_json_information("./JSONS/shared_accounts.json")
        self.hmac = HMAC()
        self.password_derivation = PasswordDerivation()
        self.symetric_encryptor = SymetricEncryptor()

    #versión para diccionario

    def add_user(self,user:str, password:str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            self.users[user]
            print("User already taken, choose another one.")
        except KeyError:
            generate_RSA_keys(user)
            self.save_users_information(user,password)
            self.external_accounts[user] = {}
            self.shared_accounts[user] = {"shared_with_me": {}, "shared_with_other":[]}
            self.save_json_information(self.external_accounts, "JSONS/users_external_accounts.json")
            self.save_json_information(self.shared_accounts, "JSONS/shared_accounts.json")


    def add_external_account(self, site:str,app_user:str,user_name: str, password: str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            json_app_users = self.recover_json_information("JSONS/app_users.json")
            json_app_users[user_name]
            print("User already taken, choose another one.")
        except KeyError:
            self.save_external_account(site,app_user,user_name,password,None,None)


    def log_in_check_user(self, user_name, user_password):
        try:
            pwderivated = self.users[user_name] #recoge la información cifrada
            key, salt = self.extract_password(pwderivated)

            if self.password_derivation.password_verification(salt,user_password,key):
                return [True,self.users]


            print("Error - User not registered!")
            return [False,None]


        except KeyError:
            #no existe
            return [False,None]

    def extract_password(self, pwderivated):
        b64_salt = pwderivated[0]
        b64_key = pwderivated[1]
        b64_salt_bytes = b64_salt.encode("ascii")
        salt = base64.urlsafe_b64decode(b64_salt_bytes)
        b64_key_bytes = b64_key.encode("ascii")
        key = base64.urlsafe_b64decode(b64_key_bytes)
        return key, salt

    # -------- Esta funcion seria parte del guardar los datos de los usuarios
    def recover_json_information(self, route):
        with open(route, "r", encoding="utf-8", newline="") as file:
            json_content = json.load(file)
        return json_content

    def save_json_information(self,dicc:dict,route:str):
        """Auxiliar method to dump a dictionary"""
        with open(route, "w", newline="") as file:
            json.dump(dicc, file, indent=2) #lo vuelcas


    def save_users_information(self,user:str,password:str):
        #función que deriva la contraseña
        password_derivated = self.password_derivation.password_derivator(str(password))
        #convertimos a bytes y luego a string para guardarlo en el json
        b64_salt, b64_key = base64.urlsafe_b64encode(password_derivated[0]), base64.urlsafe_b64encode(password_derivated[1])
        b64_string_salt, b64_string_key = b64_salt.decode("ascii"),b64_key.decode("ascii")
        self.users[user] = [b64_string_salt, b64_string_key, 0, 0]
        self.save_json_information(self.users, "./JSONS/app_users.json")

    def byte_decoded(self, password_derivated):
        b64_salt, b64_key = base64.urlsafe_b64encode(password_derivated[0]), base64.urlsafe_b64encode(
            password_derivated[1])
        b64_string_salt, b64_string_key = b64_salt.decode("ascii"), b64_key.decode("ascii")
        b64_string_password = [b64_string_salt, b64_string_key]
        return b64_string_password

    def save_external_account(self, site: str, user: str, site_user: str, password: str, sec_quest: str, notes: str,):
        # recuperamos la información antigua del external accounts
        cifr = []
        # encriptar
        try:
            list_key = self.users[user][1]

            # decodificamos key y nonce
            b64_key_bytes = list_key.encode("ascii")
            key = base64.urlsafe_b64decode(b64_key_bytes)  # key decodificada

            #guardamos la info en un str
            ciph = "User:" + str(site_user) + "," + "Password:" + str(password) + "," + "sec_quest:" + str(sec_quest) + "," + "notes:"+ str(notes)

            answer = self.symetric_encryptor.symetric_encrypt(key, ciph)  # en formato de lista, ver si da error
            for element in answer:
                bytes_element =base64.urlsafe_b64encode(element)
                el = bytes_element.decode("ascii")
                cifr.append(el)#guardamos todos los elementos que devuelve la función encrypt

            json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
            json_external_accounts[user][site] = cifr
            self.save_json_information(json_external_accounts, "./JSONS/users_external_accounts.json")

        except KeyError:
            print(ANSI_RED+"Error: unable to save account"+ANSI_RESET)


    def show(self, user:str):
        try:
            user_sites = self.recover_json_information("./JSONS/users_external_accounts.json")[user]
            key = self.users[user][1]

            b64_key = key.encode("ascii")  # Recuperamos los bytes de los strings, se codifican
            key = base64.urlsafe_b64decode(b64_key)  #

            for site in user_sites:
                if site != "shared_with_me":
                    nonce = user_sites[site][0]
                    b64_nonce = nonce.encode("ascii")
                    nonce = base64.urlsafe_b64decode(b64_nonce)

                    encrypted_message = user_sites[site][1]
                    b64_encrypted_message = encrypted_message.encode("ascii")
                    encrypted_message = base64.urlsafe_b64decode(b64_encrypted_message)

                    signature = user_sites[site][2]
                    b64_signature = signature.encode("ascii")
                    signature = base64.urlsafe_b64decode(b64_signature)

                    message = self.symetric_encryptor.symetric_decrypt(key,encrypted_message,nonce,signature)
                    print(ANSI_RED+site+":"+ANSI_RESET)
                    characters = ''
                    for i in message.decode():
                        characters += i
                        if i == ",":
                            print("\t"+ANSI_CYAN+characters +ANSI_RESET)
                            characters = ''

        except KeyError:
            print(str(user)+": {}")

    def share_password(self, user1:str, user2:str, site:str):
        """método para que user1 le comparta a user2 la contraseña de site"""

        json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
        shared_accounts = self.recover_json_information("./JSONS/shared_accounts.json")

        try:
            u1 = json_external_accounts[user1] #comprobamos que el usuario que va a compartir está registrado en external_accounts
            u2 = json_external_accounts[user2] #comprobamos que el usuario que va a compartir está registrado en external_accounts

            #si lo está, comprobamos que el site es correcto
            s1 = u1[site] #búsqueda del  site 1

            shared_accounts[user1]["shared_with_other"].append(site)
            shared_accounts[user2]['shared_with_me'][site] = s1 #se guarda en una lista la info con el sitio y la contraseña

            self.save_json_information(json_external_accounts, "./JSONS/users_external_accounts.json")
            self.save_json_information(shared_accounts, "./JSONS/shared_accounts.json")

        except KeyError: #si no ha encontrado alguno de los dos sites de los usuarios emisor y receptor
            print(ANSI_RED+"Error: unable to share password"+ANSI_RESET)

    def delete_password(self, user:str,site:str):
        """método para borrar el site de user"""
        try:
            json_external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
            del json_external_accounts[user][site]
            self.save_json_information(json_external_accounts,"./JSONS/users_external_accounts.json")


        except KeyError:
            print(ANSI_RED+"Error: site not found"+ANSI_RESET)








