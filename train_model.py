import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split, cross_val_score
import joblib

# Load training data
df = pd.read_csv("data/training_data.csv")
texts = df["text"]
labels = df["label"]

# Divide the training set and test set
X_train_texts, X_test_texts, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

# Quantitative
vectorizer = TfidfVectorizer()
X_train = vectorizer.fit_transform(X_train_texts)
X_test = vectorizer.transform(X_test_texts)

# model training
model = LogisticRegression()
model.fit(X_train, y_train)

# Model evaluation (on test set)
preds = model.predict(X_test)
probs = model.predict_proba(X_test)[:, 1]

print("✅ Model training is complete")
print("\n📊 Classification Report:\n")
print(classification_report(y_test, preds))

print("\n📊 Confusion Matrix:")
print(confusion_matrix(y_test, preds))

print("\n📈 ROC AUC Score:", round(roc_auc_score(y_test, probs), 2))

# 5-fold cross validation with all data to assess generalisability
X_all = vectorizer.fit_transform(texts)
cv_model = LogisticRegression()
cv_scores = cross_val_score(cv_model, X_all, labels, cv=5, scoring="roc_auc")
print("\n📊 5-Fold Cross-Validation ROC AUC Scores:", cv_scores)
print("📈 Average ROC AUC Score:", round(cv_scores.mean(), 4))

# Retrain and save the model using all the data
X_full = vectorizer.fit_transform(texts)
model.fit(X_full, labels)

joblib.dump(model, "model/model.pkl")
joblib.dump(vectorizer, "model/vectorizer.pkl")
