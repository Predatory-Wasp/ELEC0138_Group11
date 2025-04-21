import requests
import time
import random

# registration page URL
register_url = "http://127.0.0.1:5000/register"

# Generate fake mobile phone numbers
def generate_fake_phone(i):
    # Generate 11-digit legal mobile phone number（eg：13800000001）
    return f"1380000{str(i).zfill(4)}"

# Simulate Bulk Registration
for i in range(10):
    username = f"fakeuser{i}"
    password = "password123"
    phone = generate_fake_phone(i)

    print(f"📨 Submitting fake registration for: {username}, phone: {phone}")

    response = requests.post(register_url, data={
        "username": username,
        "password": password,
        "phone": phone
    })

    # Output response status and partial return content
    print(f"Status: {response.status_code}")
    print(f"Response preview: {response.text[:100]}")

    # Simulation of artificial delays
    time.sleep(0.1)
