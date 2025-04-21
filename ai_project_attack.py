import requests
import random
import time


# Fake Project Generation Functions
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


# Attack Script Configuration
target_url = "http://127.0.0.1:5000/create_project"
number_of_submissions = 10  # Adjustable number of times
delay_between = 1  # Interval between each commit (seconds）

# Simulated login session (when login verification can be skipped)
session = requests.Session()

for i in range(number_of_submissions):
    fake_project = generate_fake_project()
    response = session.post(target_url, data=fake_project)

    print(f"🚀 Submission {i + 1}: {fake_project['title']} → Status: {response.status_code}")

    if response.status_code == 429:
        print("⚠️ Rate limited! Stopping.")
        break

    time.sleep(delay_between)
