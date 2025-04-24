# ELEC0138 Group 11 - Crowdfunding Platform Threat Model

This project is the coursework for **UCL ELEC0138 - Group 11**, focusing on cybersecurity attack and defense experiments based on a simulated **crowdfunding platform**. It covers various types of cyberattacks, data handling, and corresponding defense strategies.

---

## 🚀 Getting Started

### 1. Install Dependencies

Before running the application, install the required Python packages:

```bash
pip install -r requirements.txt
```

### 2. Launch the Platform

Run the following command to start the terminal-based web platform:

```bash
python app.py
```

This will start a local instance of the platform, allowing you to simulate attacks and test defense mechanisms.

---

##  Branch Overview

Each branch implements a separate part of the project workflow, including data processing, web development, and various security experiments:

### 1, `Yifang-Pang` Branch - Data Processing and Web Development

- Loads, preprocesses and stores the **crowdfunding-related data**
- Builds and designs the main **structure of the website**  
- Develops different **core functionalities** of the crowdfunding platform

### 2, `Cheng-Hsuan-Hu` Branch - DDoS Attack and ML-Based Defense

- Simulates **Distributed Denial of Service (DDoS)** attacks  
- Uses **Machine Learning** to detect and defend against DDoS in real time

### 3, `Yihan-Liu` Branch - Brute Force, AI-Generated Fake Projects, and Trust Scoring

- Simulates **brute force attacks** on login credentials  
- Uses AI to generate **fake crowdfunding projects**  
- Introduces a **credibility scoring system** to evaluate project trustworthiness

### 4,`Yifei-Yuan` Branch - SQL Injection and XSS Attacks

- Demonstrates **SQL Injection** vulnerabilities and exploits  
- Simulates **Cross-Site Scripting (XSS)** attacks and implements countermeasures

---

## 📁 Project Structure

```
├── __pycache__/            # Python cache files
├── data/                   # Raw user and crowdfunding data
├── static/                 # Static resources (CSS, JS, images)
├── templates/              # HTML templates for the website
├── app.py                  # Main Flask app with routing and launch
├── database.db             # Preprocessed and structured data (SQLite)
├── main.ipynb              # Downloading and loading data
├── readme.md               # Project documentation
└── requirements.txt        # Python dependency list
```

---

## 📌 Usage Notes

Each branch is independent and contains code specific to its type of attack, data flow, or defense strategy.

To switch branches, use the following command:

```bash
git checkout branch-name
```

Make sure to install any additional dependencies if prompted when switching between branches.

---

## 👥 Authors

- ELEC0138 - Group 11  
  University College London (UCL)

This project was developed as part of the ELEC0138 coursework.

