# model/detector.py

import joblib
import os

# Dynamically resolve the absolute path to the model directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(BASE_DIR, "model.pkl")
vectorizer_path = os.path.join(BASE_DIR, "vectorizer.pkl")

# Safety check: raise an error if files not found
if not os.path.exists(model_path):
    raise FileNotFoundError(f"❌ Model file not found: {model_path}")
if not os.path.exists(vectorizer_path):
    raise FileNotFoundError(f"❌ Vectorizer file not found: {vectorizer_path}")

# Load the model and vectorizer
model = joblib.load(model_path)
vectorizer = joblib.load(vectorizer_path)

def detect_ai_generated_text(description):
    """
    Predict the trustworthiness of a project description using a trained ML model.
    Returns a score from 0.0 (suspicious) to 1.0 (trustworthy).
    """
    X = vectorizer.transform([description])
    probability = model.predict_proba(X)[0][1]
    return round(probability, 2)