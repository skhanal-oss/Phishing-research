import pandas as pd
import numpy as np

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from xgboost import XGBClassifier

df = pd.read_csv("hybrid_dataset.csv")

if "url" in df.columns:
    df = df.drop(columns=["url"])

categorical_cols = [col for col in [
    "issuer",
    "signature_algorithm",
    "tls_version",
    "cipher_suite",
]if col in df.columns] 

for col in categorical_cols:
    df[col] = df[col].fillna("unknown")
    le = LabelEncoder()
    df[col] = le.fit_transform(df[col].astype(str))

X = df.drop(columns=["label"])
y = df["label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, 
    test_size=0.2,
    random_state=42,
    stratify=y
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

models = {
    "Logistic Regression (Hybrid)": LogisticRegression(max_iter = 1000),
    "Random Forest (Hybrid)": RandomForestClassifier(
        n_estimators=200,
        random_state=42
    ),
    "XGBoost (Hybrid)": XGBClassifier(
        eval_metric = "logloss",
        random_state = 42
    )
}

def evaluate(name, model, X_test, y_test):
    y_pred = model.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred).ravel()

    return{
        "Model": name,
        "Accuracy": accuracy_score(y_test, y_pred),
        "Precision": precision_score(y_test, y_pred),
        "Recall": recall_score(y_test, y_pred),
        "F1 Score": f1_score(y_test, y_pred),
        "False Positive Rate": (fp / (fp + tn) if (fp + tn) > 0 else 0),
    }

results = []

for name, model in models.items():
    if "Logistic Regression" in name:
        model.fit(X_train_scaled, y_train)
        results.append(evaluate(name, model, X_test_scaled, y_test))
    else:
        model.fit(X_train, y_train)
        results.append(
            evaluate(name, model, X_test, y_test)
        )
results_df = pd.DataFrame(results)
results_df.to_csv("hybrid_model_results.csv", index = False)

print(results_df)
print("\nSaved to hybrid_model_results.csv")