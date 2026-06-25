import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

from xgboost import XGBClassifier

df = pd.read_csv("lexical_features.csv")

if "url" in df.columns:
    df = df.drop(columns=["url"])

X = df.drop(columns=["label"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size = 0.2, random_state = 42, stratify = y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

models = {
    "Logistic Regression": LogisticRegression(max_iter = 1000),
    "Random Forest": RandomForestClassifier(n_estimators=200, random_state=42),
    "XGBoost": XGBClassifier(
        use_label_encoder = False,
        eval_metric = "logloss",
        random_state = 42
    )
}


def evaluate_model(name, model, X_test, y_test):
    y_pred = model.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    accuracy = accuracy_score(y_test, y_pred)
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)

    false_positive_rate = (
    fp / (fp + tn) if (fp + tn) > 0 else 0)
    return {
        "Model": name, 
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1 Score": f1,
        "False Positive Rate": false_positive_rate,
        "True Positives": tp,
        "True Negatives": tn,
        "False Positives": fp,
        "False Negatives": fn
    }

results = []

for name, model in models.items():
    if name == "Logistic Regression":
        model.fit(X_train_scaled, y_train)
        results.append(evaluate_model(name, model, X_test_scaled, y_test))
    else:
        model.fit(X_train, y_train)
        results.append(evaluate_model(name, model, X_test, y_test))


results_df = pd.DataFrame(results)
results_df.to_csv("baseline_model_results.csv", index = False)

print(results_df)
print("\nResults saved to baseline_model_results.csv")