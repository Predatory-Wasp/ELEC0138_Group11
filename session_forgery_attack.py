import requests

# Suppose an attacker guesses that a user is ‘yihan’ and tries to spoof the session
target_user = "yihan"

# Construct a session cookie (to simulate that the user is logged in)
cookies = {
    "session": "invalid_session_value"  # This is the focus of the attack, the real value needs to be brute-force broken or obtained from XSS
}

# Request a /query page to test if login authentication can be bypassed
url = "http://127.0.0.1:5000/query"

response = requests.get(url, cookies=cookies)

print(f"🔍 Attempting to forge session as user: {target_user}")
print(f"Status Code: {response.status_code}")
print("Response preview:")
print(response.text[:300])
