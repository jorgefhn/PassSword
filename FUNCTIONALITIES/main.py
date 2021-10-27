from FUNCTIONALITIES import admin
import os
import time

ANSI_RESET = "\u001B[0m";
ANSI_BLACK = "\u001B[30m";
ANSI_RED = "\u001B[31m";
ANSI_GREEN = "\u001B[32m";
ANSI_YELLOW = "\u001B[33m";
ANSI_BLUE = "\u001B[34m";
ANSI_PURPLE = "\u001B[35m";
ANSI_CYAN = "\u001B[36m";
ANSI_WHITE = "\u001B[37m";

admin = admin.Admin()
os.system('cls')

print("\n"+ANSI_PURPLE+"""
 ____                  ____                              _   ____  
 |  _ \    __ _   ___  / ___|  __      __   ___    _ __  | | |  _ \ 
 | |_) |  / _` | / __| \___ \  \ \ /\ / /  / _ \  | '__| | | | | | |
 |  __/  | (_| | \__ \  ___) |  \ V  V /  | (_) | | |    | | | |_| |
 |_|      \__,_| |___/ |____/    \_/\_/    \___/  |_|    |_| |____/ 
                                                                    """+ANSI_RESET)
time.sleep(2)

while True:
    "Bucle que permite la ejecucion hasta que el usuario indique lo contrario"
    #admin.recover_json_information("./JSONS/app_users.json)
    print("__________________________________________________________")
    print(ANSI_YELLOW+"Welcome menu - Choose between actions: \n "
          "1) Login \n "
          "2) Sign up\n "
          "3) Close program"+ANSI_RESET)
    print("__________________________________________________________")
    action1 = input(ANSI_PURPLE+"Write down 1, 2 or 3: "+ANSI_RESET)
    # ---------------------- Login functionality -----------------------------
    if action1 == "1":
        os.system('cls')
        #Una vez chekeado que es un usuario registrado
        #pasamos a la interaccion de en el menu principal
        print(ANSI_PURPLE+"Login Menu - Introduce your user information:"+ANSI_RESET)
        app_user = input(ANSI_YELLOW+"Username: "+ANSI_RESET).upper()
        app_pass = input(ANSI_YELLOW+"Password: "+ANSI_RESET)
        log_in_ck = admin.log_in_check_user(app_user, app_pass)
        flag = log_in_ck[0]
        user_acc = log_in_ck[1]

        if flag:
            while True:
                os.system('cls')
                print("__________________________________________________________")
                print(ANSI_YELLOW+"Main menu - Choose between actions:\n"
                      "1) See your passwords\n"
                      "2) Add a new password\n"
                      "3) Modify a password\n"
                      "4) Share a password\n"
                      "5) Delete a password\n"
                      "6) Close current session"+ANSI_RESET)
                print("__________________________________________________________")

                action = input(ANSI_PURPLE+"Write down 1, 2, 3, 4, 5 or 6: "+ANSI_RESET)

                if action == "1":
                    os.system('cls')
                    try:
                        print("CONTRASEÑAS GUARDADAS:")
                        print("__________________________________________________________")
                        admin.show(app_user)
                        print("__________________________________________________________")
                        input(ANSI_RED+"Presiona cualquier tecla para continuar: "+ANSI_RESET)
                    except KeyError:
                        admin.external_accounts[app_user] = {"shared": {}}
                        admin.save_json_information(admin.external_accounts,"./JSONS/users_external_accounts.json")

                if action == "2":
                    os.system("cls")
                    print(ANSI_PURPLE+"Add a new password - Introduce the account information"+ANSI_RESET)
                    acc_site = input(ANSI_YELLOW+"Introduce the site of the account: ").upper()
                    acc_user = input("Introduce the user of the account: ")
                    acc_pass = input("Introduce the password of the account: "+ANSI_RESET)
                    admin.add_external_account(acc_site,app_user,acc_user,acc_pass)

                if action == "3":
                    os.system("cls")
                    print(ANSI_PURPLE+"Modify info - Introduce the required data"+ANSI_RESET)
                    site = input(ANSI_YELLOW+"Introduce the site/application: ").upper()
                    new_acc_user = input("Introduce the new user: ")
                    new_acc_pass = input("Introduce the new password: ")
                    new_acc_sec_ques = input("Introduce the new security question: ")
                    new_acc_notes = input("Introduce the new notes: "+ANSI_RESET)
                    admin.save_external_account(site,
                                                app_user,
                                                new_acc_user,
                                                new_acc_pass,
                                                new_acc_sec_ques,
                                                new_acc_notes,
                                                admin.external_accounts[app_user]['shared'])

                if action == "4":
                    os.system("cls")
                    print(ANSI_PURPLE+"Share a password - Introduce the required data"+ANSI_RESET)
                    receiving_user = input(ANSI_YELLOW+"Introduce the user which you will like to share your account: ")
                    site_to_share = input("Introduce the site of the account you want to share: "+ANSI_RESET)
                    admin.share_password(app_user,receiving_user,site_to_share)

                if action == "5":
                    os.system("cls")
                    print(ANSI_PURPLE+"Delete a password - Introduce the required data"+ANSI_RESET)
                    site = input(ANSI_YELLOW+"Introduce the site/application that you would like to delete: "+ANSI_YELLOW).upper()
                    admin.delete_password(app_user,site)

                if action == "6":
                    os.system('cls')

                    break

                '''if int(action) not in (1,7):
                    print("Wrong answer, try again!")
                    time.sleep(2)'''
        else:
            os.system("cls")
            print("Invalid credentials, please try again")
            time.sleep(1)

    # ---------------------- Sing up functionality -----------------------------
    elif action1 == "2":
        os.system('cls')
        print(ANSI_PURPLE+"\nSign up - New User"+ANSI_RESET)
        app_user = input(ANSI_YELLOW+"Username: ").upper()
        app_pass = input("Password: "+ANSI_RESET)
        admin.add_user(app_user, app_pass)

    # ---------------------- Close functionality -----------------------------
    elif action1 == "3":
        #admin.save_users_information()
        os.system("cls")
        print("Thanks for using PassSworld!!")

        break

    # ---------------------- Input error functionality -----------------------------

    else:
        print("Error: action not possible")
