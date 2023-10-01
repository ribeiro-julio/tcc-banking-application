import requests
import os
from getpass import getpass
import time

def get_me(session: str) -> dict:
    response = requests.get("http://localhost:3000/api/me", 
                            headers = {"Authorization": f"Bearer {session}"})
    
    if response.status_code == 200:
        return {"name": response.json()["name"], 
                "balance": response.json()["balance"]}
    
    return {"name": None, "balance": None}

def patch_password(session: str) -> None:
    while True:
        os.system("clear")

        print("Digite a senha atual:")
        old_password = getpass(prompt = "")

        print("Digite a nova senha:")
        new_password = getpass(prompt = "")

        print("Confirme a nova senha:")
        new_password_confirmation = getpass(prompt = "")

        response = requests.patch("http://localhost:3000/api/me/password", 
                                  headers = {"Authorization": f"Bearer {session}"}, 
                                  json = {"oldPassword": old_password, 
                                          "newPassword": new_password, 
                                          "newPasswordConfirmation": new_password_confirmation})
        
        if response.status_code == 200:
            print("\nSenha alterada com sucesso")
            time.sleep(1)
            
            return None
        
        while True:
            os.system("clear")

            print(f"Erro ao trocar a senha - API respondeu: {response.status_code}: {response.json()}")

            print("\n1. Tentar novamente")
            print("0. Cancelar")
            opcao = input()

            if opcao == "1": break
            if opcao == "0": return None

def patch_pin(session: str) -> None:
    while True:
        os.system("clear")

        print("Digite o PIN atual:")
        old_pin = getpass(prompt = "")

        print("Digite o novo PIN:")
        new_pin = getpass(prompt = "")

        print("Confirme o novo PIN:")
        new_pin_confirmation = getpass(prompt = "")

        response = requests.patch("http://localhost:3000/api/me/pin", 
                                  headers = {"Authorization": f"Bearer {session}"}, 
                                  json = {"oldPin": old_pin, 
                                          "newPin": new_pin, 
                                          "newPinConfirmation": new_pin_confirmation})
        
        if response.status_code == 200:
            print("\nPIN alterado com sucesso")
            time.sleep(1)
            
            return None
        
        while True:
            os.system("clear")

            print(f"Erro ao trocar o PIN - API respondeu: {response.status_code}: {response.json()}")

            print("\n1. Tentar novamente")
            print("0. Cancelar")
            opcao = input()

            if opcao == "1": break
            if opcao == "0": return None
