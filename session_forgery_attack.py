import requests

# 假设攻击者猜测某个用户是 "admin"，尝试伪造会话
target_user = "yihan"

# 构造 session cookie（模拟用户已登录）
cookies = {
    "session": "invalid_session_value"  # 👈 这是攻击的重点，真实值需要暴力破解或从 XSS 获得
}

# 请求 /query 页面，测试是否可以绕过登录验证
url = "http://127.0.0.1:5000/query"

response = requests.get(url, cookies=cookies)

print(f"🔍 Attempting to forge session as user: {target_user}")
print(f"Status Code: {response.status_code}")
print("Response preview:")
print(response.text[:300])