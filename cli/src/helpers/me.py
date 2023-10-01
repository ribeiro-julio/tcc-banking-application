import requests

def get_me(session: str) -> dict:
    response = requests.get("http://localhost:3000/api/me", 
                            headers = {"Authorization": f"Bearer {session}"})
    
    if response.status_code == 200:
        return {"name": response.json()["name"], 
                "balance": response.json()["balance"]}
    
    return {"name": None, "balance": None}
