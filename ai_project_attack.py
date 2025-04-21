import requests
import random
import time


# 伪造项目生成函数
def generate_fake_project():
    titles = ["Urgent Help", "Medical Crisis", "Orphan Fund", "Emergency Aid"]
    descriptions = [
        "My child needs urgent surgery, please support us now.",
        "We are out of money and need help to survive.",
        "Please donate to help my family in this tragic time.",
        "I'm facing eviction without your support.",
    ]
    return {
        "title": random.choice(titles),
        "description": random.choice(descriptions)
    }


# 攻击脚本配置
target_url = "http://127.0.0.1:5000/create_project"
number_of_submissions = 10  # 可调整次数
delay_between = 1  # 每次提交之间的间隔（秒）

# 模拟登录会话（可跳过登录验证时）
session = requests.Session()

for i in range(number_of_submissions):
    fake_project = generate_fake_project()
    response = session.post(target_url, data=fake_project)

    print(f"🚀 Submission {i + 1}: {fake_project['title']} → Status: {response.status_code}")

    if response.status_code == 429:
        print("⚠️ Rate limited! Stopping.")
        break

    time.sleep(delay_between)