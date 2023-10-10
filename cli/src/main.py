import os

from helpers.me import get_me, patch_password, patch_pin
from helpers.login import login
from helpers.transfer import transfer_money
from helpers.otp import configure_otp

def main():
    session = None

    while True:
        os.system("clear")

        print("TCC Banking Application")

        me = get_me(session)

        print(f"\nBem-vindo {me['name']}. Seu saldo atual é c$ {me['balance']}")
        
        print("\nSelecione uma opção:")
        print("1. Entrar")
        print("2. Realizar transferência")
        print("3. Configurar autenticação de dois fatores")
        print("4. Trocar senha de acesso")
        print("5. Trocar PIN")
        print("0. Sair")
        
        opcao = input()

        if opcao == "1":
            session = login()
            continue

        if opcao == "2":
            transfer_money(session)
            continue

        if opcao == "3":
            session = configure_otp(session)
            continue

        if opcao == "4":
            patch_password(session)
            continue

        if opcao == "5":
            patch_pin(session)
            continue

        if opcao == "0":
            os.system("clear")
            print("Até logo")
            return

if __name__ == "__main__":
    main()
