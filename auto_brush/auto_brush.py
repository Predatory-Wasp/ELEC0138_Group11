import requests
import random
import time

# 基本配置，请根据实际测试环境修改
BASE_URL = "http://127.0.0.1:5000"  # 你的测试环境URL
LOGIN_URL = f"{BASE_URL}/"  # 登录页面地址（在你的 app.py 中，"/" 为登录路由）
DONATE_URL = f"{BASE_URL}/donate"  # 捐献页面地址

# 创建会话对象，保持登录状态（Cookie）
session = requests.Session()

# 模拟登录，使用测试账户（请替换为实际存在的测试账户）
login_data = {
    "username": "Scotty",  # 测试用户名
    "password": "domino"  # 测试密码
}

login_response = session.post(LOGIN_URL, data=login_data)
print("登录状态码：", login_response.status_code)
if login_response.status_code != 200:
    print("登录失败，请确认测试账户信息。")
    exit(1)


# 定义模拟捐献请求的函数
def simulate_donation(order_index):
    # 随机生成捐献金额、捐献方式和留言内容
    amount = str(random.randint(10, 100))  # 捐献金额，在10到100之间
    method = random.choice(["paypal", "credit", "bank"])  # 随机选择一种支付方式
    message = f"测试捐献订单 {order_index} - 随机数 {random.randint(1000, 9999)}"

    # 构造POST数据，与 /donate 路由中表单字段匹配
    donation_data = {
        "amount": amount,
        "method": method,
        "message": message
    }

    # 提交捐献请求
    response = session.post(DONATE_URL, data=donation_data)
    print(f"订单 {order_index} 提交状态：", response.status_code)
    # 可以根据需要打印返回内容： print(response.text)


# 模拟连续提交订单请求
ORDER_COUNT = 50  # 总共提交50个订单请求
for i in range(1, ORDER_COUNT + 1):
    simulate_donation(i)
    # 加入随机延时，模拟真实用户行为，避免全部请求瞬间到达
    time.sleep(random.uniform(0.2, 1.0))
