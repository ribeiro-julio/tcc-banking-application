import os
import requests

def transfer_money(session: str) -> None:
    while True:
        os.system("clear")

        print("Digite a quantidade a ser transferida:")
        amount = input()

        print("Digite o email do destinatário:")
        destination = input()

        print("Digite o seu PIN:")
        pin = input()

        response = requests.post("http://localhost:3000/api/transfer", 
                                 headers = {"Authorization": f"Bearer {session}"}, 
                                 json = {"amount": amount, "destination": destination, "pin": pin})

        while True:
            os.system("clear")

            if response.status_code == 200:
                print("Transferência realizada com sucesso")
                print("\nComprovante:")
                print(f"Origem: {response.json()['confirmation']['origin']['name']} - {response.json()['confirmation']['origin']['email']}")
                print(f"Destino: {response.json()['confirmation']['destination']['name']} - {response.json()['confirmation']['destination']['email']}")
                print(f"Quantidade: {response.json()['confirmation']['amount']}")

                print("\n1. Continuar")
                opcao = input()

                if opcao == "1": return None
            
            else:
                print(f"Erro ao realizar transferência - API respondeu: {response.status_code}: {response.json()}")

                print("\n1. Tentar novamente")
                print("0. Cancelar")
                opcao = input()

                if opcao == "1": break
                if opcao == "0": return None
