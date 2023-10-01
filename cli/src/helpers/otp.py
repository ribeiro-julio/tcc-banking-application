import os
import requests
import time

def check_otp(session: str, method: str) -> str | None:
    while True:
        os.system("clear")

        print("Digite o código OTP:")
        code = input()

        # used when user already has OTP activated
        url = "http://localhost:3000/api/otp/validate"
        # used when then user is activating OTP
        if method == "verify": url = "http://localhost:3000/api/otp/verify"

        response = requests.post(url, 
                                 headers = {"Authorization": f"Bearer {session}"}, 
                                 json = {"token": code})

        if response.status_code == 200: return response.json()["token"]

        while True:
            os.system("clear")

            print(f"Erro ao verificar o código OTP - API respondeu: {response.status_code}: {response.json()}")

            print("\n1. Tentar novamente")
            print("0. Cancelar")
            opcao = input()

            if opcao == "1": break
            if opcao == "0": return None

def configure_otp(session: str) -> str:
    while True:
        os.system("clear")

        print("1. Ativar OTP")
        print("2. Desativar OTP")
        print("0. Voltar")
        opcao = input()

        if opcao == "1": return enable_otp(session)
        if opcao == "2": return disable_otp(session)
        if opcao == "0": return session

def enable_otp(session: str) -> str:
    while True:
        os.system("clear")
        
        response = requests.post("http://localhost:3000/api/otp/generate", 
                                 headers = {"Authorization": f"Bearer {session}"})
        
        while True:
            os.system("clear")

            if response.status_code != 200:
                print(f"Erro ao ativar o OTP - API respondeu: {response.status_code}: {response.json()}")

                print("\n1. Tentar novamente")
                print("0. Cancelar")
                opcao = input()

                if opcao == "1": break
                if opcao == "0": return session
            else:
                print("Use esse código para configurar o OTP no Google Authenticator (ou outro aplicativo compatível):")
                print(response.json()["secret"])

                print("\n1. Continuar")
                print("0. Cancelar")
                opcao = input()

                if opcao == "1":
                    token = check_otp(session, "verify")
                    if token == None: return session
                    
                    print("\nOTP ativado com sucesso")
                    time.sleep(1)
                    
                    return token
                
                if opcao == "0": return session

def disable_otp(session: str) -> str:
    while True:
        os.system("clear")

        token = check_otp(session, "validate")
        if token == None: return session

        response = requests.post("http://localhost:3000/api/otp/disable", 
                                 headers = {"Authorization": f"Bearer {session}"})
        
        if response.status_code == 200:
            print("OTP desativado com sucesso")
            time.sleep(1)
            
            return response.json()["token"]

        while True:
            os.system("clear")

            print(f"Erro ao desativar o OTP - API respondeu: {response.status_code}: {response.json()}")

            print("\n1. Tentar novamente")
            print("0. Cancelar")
            opcao = input()

            if opcao == "1": break
            if opcao == "0": return session
