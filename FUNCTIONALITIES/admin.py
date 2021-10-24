
import time
import json


class Admin:
    def __init__(self):
        self.users = self.recover_json_information("./JSONS/app_users.json")["App_users"]
        self.external_accounts = self.recover_json_information("./JSONS/users_external_accounts.json")

    #versión para diccionario

    def add_user(self,user:str, password:str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            a = self.users[user]
            print("User already taken, choose another one.")
        except KeyError:
            self.save_users_information(user,password)

    def add_external_account(self, site:str,app_user:str,user_name: str, password: str):
        try:
            # Si no hay error es que el usuario existe y por ello imprimimos el mensaje
            a = self.users[user_name]
            print("User already taken, choose another one.")
        except KeyError:
            self.save_external_account(site,app_user,user_name,password,None,None, self.external_accounts[app_user]["shared"])


    def log_in_check_user(self, user_name, user_password):
        try:
            if self.users[user_name] == user_password:
                return [True,self.users]
            print("Error - User not registered!")
            return [False,None]
            #si existe, está bien


        except KeyError:
            #no existe
            return [False,None]

    # -------- Esta funcion seria parte del guardar los datos de los usuarios
    def recover_json_information(self, route):
        with open(route, "r", encoding="utf-8", newline="") as file:
            json_content = json.load(file)
        return json_content

    def save_json_information(self,dicc:dict,route:str):
        """Auxiliar method to dump a dictionary"""
        with open(route, "w", encoding="utf-8", newline="") as file:
            json.dump(dicc, file, indent=2) #lo vuelcas


    def save_users_information(self,user:str,password:str):
        #app_user_dic = self.recover_json_information("./JSONS/app_users.jsons")#diccionario nuevo que se mete
        self.users[user] = password #metemos la nueva password
        app_user = {"App_users": self.users}  # lo actualizas
        self.save_json_information(app_user,"./JSONS/app_users.json")



    def save_external_account(self, site:str,user:str,site_user:str,password:str,sec_quest:str,notes:str,shared:dict):
        # recuperamos la información antigua del external accounts

        ac = [site_user,password,sec_quest,notes]
        self.external_accounts[user][site] = ac  # introduces la nueva info
        self.external_accounts[user]["shared"] = shared
        self.save_json_information(self.external_accounts,"./JSONS/users_external_accounts.json")


    def share_password(self,user1:str,user2:str,site:str):
        """método para que user1 le comparta a user2 la contraseña de site"""
        try:
            u1 = self.external_accounts[user1] #comprobamos que el usuario que va a compartir está registrado en external_accounts
            u2 = self.external_accounts[user2] #comprobamos que el usuario que va a compartir está registrado en external_accounts
            #si lo está, comprobamos que el site es correcto
            s1 = u1[site] #búsqueda del  site 1
            s2 = u2[site] #búsqueda del  site 2
            #si llega hasta aquí, correcto

            print("Hasta aquí si que llega")
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
            print(str(self.external_accounts))
            self.save_json_information(self.external_accounts,"./JSONS/users_external_accounts.json")


        except KeyError:
            print("Usuario no contenía el site")







