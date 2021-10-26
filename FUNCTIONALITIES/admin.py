
import time
import json
from cyber_security import SymetricEncryptor,HMAC,PasswordDerivation
import base64


class Admin:
    def __init__(self):
        self.users = self.recover_json_information("./JSONS/app_users.json")["App_users"]
        self.external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")
        self.hmac = HMAC()
        self.password_derivation = PasswordDerivation()
        self.symetric_encryptor = SymetricEncryptor()

    #versión para diccionario

    def add_user(self,user:str, password:str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            a = self.users[user]
            print("User already taken, choose another one.")
        except KeyError:
            self.save_users_information(user,password)
            self.external_accounts[user] = {"shared": {}}
            self.save_json_information(self.external_accounts,"JSONS/users_external_accounts.json")


    def add_external_account(self, site:str,app_user:str,user_name: str, password: str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            a = self.users[user_name]
            print("User already taken, choose another one.")
        except KeyError:
            self.external_accounts[app_user] = {"shared": {}}
            self.save_external_account(site,app_user,user_name,password,None,None, self.external_accounts[app_user]["shared"])


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
        b64_salt,b64_key = base64.urlsafe_b64encode(password_derivated[0]),base64.urlsafe_b64encode(password_derivated[1])
        b64_string_salt,b64_string_key = b64_salt.decode("ascii"),b64_key.decode("ascii")
        b64_string_password = [b64_string_salt,b64_string_key]
        #guardamos contraseña
        self.users[user] = b64_string_password  # metemos la clave y el salt
        app_user = {"App_users": self.users}  # lo actualizas
        self.save_json_information(app_user, "./JSONS/app_users.json")

    def byte_decoded(self, password_derivated):
        b64_salt, b64_key = base64.urlsafe_b64encode(password_derivated[0]), base64.urlsafe_b64encode(
            password_derivated[1])
        b64_string_salt, b64_string_key = b64_salt.decode("ascii"), b64_key.decode("ascii")
        b64_string_password = [b64_string_salt, b64_string_key]
        return b64_string_password

    def save_external_account(self, site: str, user: str, site_user: str, password: str, sec_quest: str, notes: str,
                              shared: dict):
        # recuperamos la información antigua del external accounts
        ac = [site_user, password, sec_quest, notes]
        cifr = []
        # encriptar
        try:
            list_key = self.users[user][1]
            # decodificamos key y nonce
            b64_key_bytes = list_key.encode("ascii")
            key = base64.urlsafe_b64decode(b64_key_bytes)  # key decodificada


            #guardamos la info en un str
            ciph = "User:"+str(ac[0]) + "," + "Password:"+str(ac[1]) + "," + "sec_quest:"+str(ac[2]) + "," + "notes:"+str(ac[3])

            answer = self.symetric_encryptor.symetric_encrypt(key, ciph)  # en formato de lista, ver si da error
            for element in answer:
                bytes_element =base64.urlsafe_b64encode(element)
                el = bytes_element.decode("ascii")
                cifr.append(el)#guardamos todos los elementos que devuelve la función encrypt

            self.external_accounts[user][site] = cifr  # introduces la nueva info con el nonce incluido
            self.external_accounts[user]["shared"] = shared
            self.save_json_information(self.external_accounts, "./JSONS/users_external_accounts.json")

        except KeyError:
            print("Error:")


    def show(self, user:str):
        try:
            user_sites = self.external_accounts[user]
            key = self.users[user][1]

            b64_key = key.encode("ascii")  # Recuperamos los bytes de los strings, se codifican
            key = base64.urlsafe_b64decode(b64_key)  #

            for site in user_sites:
                if site != "shared":
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
                    print(site+":"+str(message.decode()))

        except KeyError:
            print(str(user)+": {}")




    def share_password(self,user1:str,user2:str,site:str):
        """método para que user1 le comparta a user2 la contraseña de site"""
        try:
            u1 = self.external_accounts[user1] #comprobamos que el usuario que va a compartir está registrado en external_accounts
            u2 = self.external_accounts[user2] #comprobamos que el usuario que va a compartir está registrado en external_accounts
            #si lo está, comprobamos que el site es correcto
            s1 = u1[site] #búsqueda del  site 1
            s2 = u2[site] #búsqueda del  site 2
            #si llega hasta aquí, correcto

            self.external_accounts[user2]['shared'] = [site,s1[0]] #se guarda en una lista la info con el sitio y la contraseña
            self.external_accounts[user1]['shared'] = [site,s2[0]] #se guarda en una lista la info con el sitio y la contraseña

            print(self.external_accounts)
            self.save_json_information(self.external_accounts,"./JSONS/users_external_accounts.json")


        except KeyError: #si no ha encontrado alguno de los dos sites de los usuarios emisor y receptor
            print("Error al compartir contraseña")

    def delete_password(self, user:str,site:str):
        """método para borrar el site de user"""
        try:

            del self.external_accounts[user][site]
            self.save_json_information(self.external_accounts,"./JSONS/users_external_accounts.json")


        except KeyError:
            print("Usuario no contenía el site")








