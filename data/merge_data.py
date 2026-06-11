import pandas as pd

legitimate_df = pd.read_csv("data/top-1m.csv")
phishing_df = pd.read_csv("data/verified_online.csv")


legitimate_url_column = "google.com"
phishing_url_column = "url"

phishing_df["label"] = 1

legitimate_rows = pd.DataFrame(columns=phishing_df.columns)

legitimate_rows["phish_id"] = legitimate_df["1"]
legitimate_rows[phishing_url_column] = legitimate_df[legitimate_url_column]
legitimate_rows["label"] = 0


merged_df = pd.concat([phishing_df, legitimate_rows], ignore_index = True)

merged_df.to_csv("merged_labeled.csv", index = False)

print(f"Saved {len(merged_df)} rows to merged_labeled.csv")

