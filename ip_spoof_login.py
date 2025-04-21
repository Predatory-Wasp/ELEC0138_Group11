import requests

# Emulating Multiple Source IP Addresses
ip_list = [
    "1.2.3.4",
    "8.8.8.8",
    "101.200.50.1",
    "192.168.1.99",  # LAN testing
    "222.186.30.15"
]

# target address
login_url = "http://127.0.0.1:5000/"

# Correct account password (registered in advance）
username = "yihan"
password = "lyh2002626"  # real password

for spoof_ip in ip_list:
    headers = {
        "X-Forwarded-For": spoof_ip
    }

    print(f"\n🚨 Simulating login from IP: {spoof_ip}")

    response = requests.post(login_url, headers=headers, data={
        "username": username,
        "password": password
    })

    # Outputs the response & determines whether to enter the validation phase
    print(f"Response status: {response.status_code}")
    print("Redirected to:", response.url)

    if "verify" in response.url:
        print("✅ Login reached verification stage.\n")
    else:
        print("❌ Login failed.\n")
