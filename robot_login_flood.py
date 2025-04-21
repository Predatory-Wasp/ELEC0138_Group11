import requests
import time

# login interface address
url = "http://127.0.0.1:5000/"

# Analogue username + correct password 
username = "admin"
password = "password123"

# One request per second to simulate continuous robot access
for i in range(30):
    response = requests.post(url, data={
        "username": username,
        "password": password
    })

    print(f"[{i+1}] Request sent, status: {response.status_code}")

    # Observe whether the console sends CAPTCHA frequently
    time.sleep(1)  # Request frequency
