import os
from getpass import getpass
import requests
import jwt
import time

from .env import JWT_SECRET
from .otp import check_otp

def login() -> str | None:
    while True:
        os.system("clear")

        print("Digite seu email:")
        email = input()

        print("Digite sua senha:")
        password = getpass()

        response = requests.post("http://localhost:3000/api/login", 
                                 json = {"email": email, "password": password})

        if response.status_code == 200:
            token = response.json()["token"]
            token_data = jwt.decode(token, 
                                    key = JWT_SECRET, 
                                    algorithms = ["HS256"])

            if token_data["authorized"] == False: token = check_otp(token, "validate")
            if token == None: return None

            print("\nLogin realizado com sucesso")
            time.sleep(1)
            
            return token
        
        while True:
            os.system("clear")

            print(f"Erro no login - API respondeu: {response.status_code}: {response.json()}")

            print("\n1. Tentar novamente")
            print("0. Cancelar")
            opcao = input()

            if opcao == "1": break
            if opcao == "0": return None
