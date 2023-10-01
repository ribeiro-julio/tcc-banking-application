import os

from helpers.login import login
from helpers.otp import configure_otp

def main():
    session = None

    while True:
        os.system("clear")

        print("TCC Banking Application\n")
        
        print("Selecione uma opção:")
        if session == None:
            print("1. Entrar")
            print("0. Sair")
        else:
            print("1. Ver saldo")
            print("2. Realizar transfêrencia")
            print("3. Configurar autenticação de dois fatores")
            print("4. Trocar senha de acesso")
            print("5. Trocar PIN")
            print("0. Sair")
        
        opcao = input()

        if opcao == "1" and session == None:
            session = login()
            continue

        if opcao == "1" and session != None:
            # Ver saldo
            continue

        if opcao == "2":
            # Realizar transferencia
            continue

        if opcao == "3":
            session = configure_otp(session)
            continue

        if opcao == "4":
            # Trocar senha de acesso
            continue

        if opcao == "5":
            # Trocar PIN
            continue

        if opcao == "0":
            os.system("clear")
            print("Até logo")
            return

if __name__ == "__main__":
    main()
