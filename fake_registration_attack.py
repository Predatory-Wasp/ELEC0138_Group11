import requests
import time
import random

# 注册页面 URL
register_url = "http://127.0.0.1:5000/register"

# 生成虚假手机号
def generate_fake_phone(i):
    # 生成 11 位合法格式的手机号码（例如：13800000001）
    return f"1380000{str(i).zfill(4)}"

# 模拟批量注册
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

    # 输出响应状态与部分返回内容
    print(f"Status: {response.status_code}")
    print(f"Response preview: {response.text[:100]}")

    # 模拟人为延迟（可去掉）
    time.sleep(0.1)