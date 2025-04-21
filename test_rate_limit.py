import requests
import time

url = "http://127.0.0.1:5000/register"

for i in range(6): 
    data = {
        "username": f"testuser{i}",
        "password": "testpass123",
        "phone": f"138000000{i:02}" 
    }

    response = requests.post(url, data=data)
    print(f"Request {i+1} => Status: {response.status_code}, Response: {response.text[:80]}")

    time.sleep(0.2)
