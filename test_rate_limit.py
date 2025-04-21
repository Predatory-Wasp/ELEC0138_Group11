import requests
import time

url = "http://127.0.0.1:5000/register"

for i in range(6):  # 尝试 6 次，超过限速设定
    data = {
        "username": f"testuser{i}",
        "password": "testpass123",
        "phone": f"138000000{i:02}"  # 合法手机号
    }

    response = requests.post(url, data=data)
    print(f"Request {i+1} => Status: {response.status_code}, Response: {response.text[:80]}")

    # 可选：控制请求间隔（减少延迟可触发限速）
    time.sleep(0.2)