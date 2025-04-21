import requests

# 模拟多个来源 IP 地址
ip_list = [
    "1.2.3.4",
    "8.8.8.8",
    "101.200.50.1",
    "192.168.1.99",  # 局域网测试
    "222.186.30.15"
]

# 目标地址
login_url = "http://127.0.0.1:5000/"

# 正确的账号密码（你必须提前注册）
username = "yihan"
password = "lyh2002626"  # 请替换为真实密码

for spoof_ip in ip_list:
    headers = {
        "X-Forwarded-For": spoof_ip
    }

    print(f"\n🚨 Simulating login from IP: {spoof_ip}")

    response = requests.post(login_url, headers=headers, data={
        "username": username,
        "password": password
    })

    # 输出响应内容 & 判断是否进入验证阶段
    print(f"Response status: {response.status_code}")
    print("Redirected to:", response.url)

    if "verify" in response.url:
        print("✅ Login reached verification stage.\n")
    else:
        print("❌ Login failed.\n")