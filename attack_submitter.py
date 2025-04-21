# attack_submitter.py

import requests
import random
import time

# Simulating AI Fake Crowdfunding Project Descriptions
fake_descriptions = [
    "My child needs urgent surgery. We are desperate. Please donate now.",
    "Emergency! We have no money left and time is running out.",
    "Our baby is sick and we can't afford the treatment.",
    "My wife is in a coma. We need $10,000 immediately.",
    "Life or death situation. Your help could save a life.",
]

# Random Headlines
def random_title():
    return random.choice([
        "Emergency Help Needed",
        "Save Our Child",
        "Support Our Family",
        "Medical Crisis Support",
        "Urgent Donation Request"
    ])

# Number of submissions
num_submissions = 5



for i in range(num_submissions):
    payload = {
        "title": random_title(),
        "description": random.choice(fake_descriptions)
    }

    response = requests.post("http://127.0.0.1:5000/create_project", data=payload)

    print(f"✅ Submitted #{i+1} - Status: {response.status_code}")
    time.sleep(1) 
