import os

from helpers.me import get_me, patch_password, patch_pin
from helpers.login import login
from helpers.otp import configure_otp

def main():
    session = None

    while True:
        os.system("clear")

        print("TCC Banking Application")
        
        if session == None:
            print("\nSelecione uma opção:")
            print("1. Entrar")
            print("0. Sair")
        else:
            me = get_me(session)

            print(f"\nBem-vindo {me['name']}. Seu saldo atual é R$ {me['balance']}")
            
            print("\nSelecione uma opção:")
            print("1. Realizar transferência")
            print("2. Configurar autenticação de dois fatores")
            print("3. Trocar senha de acesso")
            print("4. Trocar PIN")
            print("0. Sair")
        
        opcao = input()

        if opcao == "1" and session == None:
            session = login()
            continue

        if opcao == "1" and session != None:
            # Realizar transferencia
            continue

        if opcao == "2":
            session = configure_otp(session)
            continue

        if opcao == "3":
            patch_password(session)
            continue

        if opcao == "4":
            patch_pin(session)
            continue

        if opcao == "0":
            os.system("clear")
            print("Até logo")
            return

if __name__ == "__main__":
    main()
