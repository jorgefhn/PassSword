from FUNCTIONALITIES import admin
import os
import time

admin = admin.Admin()
os.system('cls')

print("Welcome to PassSword!!!\n")
time.sleep(2)

while True:
    "Bucle que permite la ejecucion hasta que el usuario indique lo contrario"
    #admin.recover_json_information("./JSONS/app_users.json)
    os.system('cls')
    print("Welcome menu - Choose between actions: \n "
          "1) Login \n "
          "2) Sign up\n "
          "3) Close program")
    action1 = input("Write down 1, 2 or 3: ")

    # ---------------------- Login functionality -----------------------------
    if action1 == "1":
        os.system('cls')
        #Una vez chekeado que es un usuario registrado
        #pasamos a la interaccion de en el menu principal
        print("Login Menu - Introduce your user information:")
        app_user = input("Username: ")
        app_pass = input("Password: ")
        input("Please press enter to confirm")
        log_in_ck = admin.log_in_check_user(app_user, app_pass)
        flag = log_in_ck[0]
        user_acc = log_in_ck[1]

        if flag:
            while True:
                os.system('cls')
                print("Main menu - Choose between actions:\n"
                      "1) See your passwords\n"
                      "2) Add a new password\n"
                      "3) Modify a password\n"
                      "4) Share a password\n"
                      "5) Delete a password\n"
                      "6) Close current session")

                action = input("Write down 1, 2, 3, 4, 5 or 6: ")

                if action == "1":
                    try:
                        print("CONTRASEÑAS GUARDADAS:")
                        admin.show(app_user)
                    except KeyError:
                        admin.external_accounts[app_user] = {"shared": {}}
                        admin.save_json_information(admin.external_accounts,"./JSONS/users_external_accounts.json")

                if action == "2":
                    os.system("cls")
                    print("Add a new password - Introduce the account information")
                    acc_site = input("Introduce the site of the account: ")
                    acc_user = input("Introduce the user of the account: ")
                    acc_pass = input("Introduce the password of the account: ")
                    admin.add_external_account(acc_site,app_user,acc_user,acc_pass)

                if action == "3":
                    os.system("cls")
                    print("Modify info - Introduce the required data")
                    site = input("Introduce the site/application: ")
                    new_acc_user = input("Introduce the new user: ")
                    new_acc_pass = input("Introduce the new password: ")
                    new_acc_sec_ques = input("Introduce the new security question: ")
                    new_acc_notes = input("Introduce the new notes: ")
                    admin.save_external_account(site,
                                                app_user,
                                                new_acc_user,
                                                new_acc_pass,
                                                new_acc_sec_ques,
                                                new_acc_notes,
                                                admin.external_accounts[app_user]['shared'])


                if action == "4":
                    os.system("cls")
                    print("Share a password - Introduce the required data")
                    receiving_user = input("Introduce the user which you will like to share your account: ")
                    site_to_share = input("Introduce the site of the account you want to share: ")
                    admin.share_password(app_user,receiving_user,site_to_share)


                if action == "5":
                    os.system("cls")
                    print("Delete a password - Introduce the required data")
                    site = input("Introduce the site/application that you would like to delete: ")
                    admin.delete_password(app_user,site)

                if action == "6":

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
        print("Sign up - New User")
        app_user = input("Username: ")
        app_pass = input("Password: ")
        admin.add_user(app_user, app_pass)

    # ---------------------- Close functionality -----------------------------
    elif action1 == "3":
        #admin.save_users_information()
        os.system("cls")
        print("Thanks for using PassSword!!")

        break

    # ---------------------- Input error functionality -----------------------------

    else:
        print("Error: action not possible")
