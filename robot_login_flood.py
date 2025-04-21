import requests
import time

# 登录接口地址
url = "http://127.0.0.1:5000/"

# 模拟用户名 + 正确密码（也可以改成错误密码爆破）
username = "admin"
password = "password123"

# 每秒请求一次，模拟机器人持续访问
for i in range(30):
    response = requests.post(url, data={
        "username": username,
        "password": password
    })

    print(f"[{i+1}] Request sent, status: {response.status_code}")

    # 可观察控制台是否频繁发送验证码
    time.sleep(1)  # ⏱️ 请求频率（可改为 0.2s 更具攻击性）