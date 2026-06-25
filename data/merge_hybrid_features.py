import pandas as pd

#File paths
LEXICAL_DATASET = r"lexical_features.csv"
SSL_TLS_DATASET = "ssl_tls_features.csv"

OUTPUT_DATASET = "hybrid_dataset.csv"

#Loading datasets
print("[INFO] Loading lexical dataset...")

lexical_df = pd.read_csv(
    LEXICAL_DATASET,
    low_memory = False
)

print(
    f"[INFO] Lexical rows: {len(lexical_df)}"
)

print("[INFO] Loading SSL/TLS dataset....")

ssl_df = pd.read_csv(
    SSL_TLS_DATASET,
    low_memory = False
)

print(
    f"[INFO] SSL/TLS rows: {len(ssl_df)}"
)

#Removing duplicates
lexical_df = lexical_df.drop_duplicates(
    subset = ["url"]
)

ssl_df = ssl_df.drop_duplicates(
    subset = ["url"]
)

print(f"[INFO] Unique lexical URLs: "
      f"{len(lexical_df)}")

print(
    f"[INFO] Unique SSL/TLS URLs: "
    f"{len(ssl_df)}"
)

if "label" in lexical_df.columns and "label" in ssl_df.columns:
    print("[INFO] Checking label consistency...")

    label_check = pd.merge(
        lexical_df[["url", "label"]],
        ssl_df[["url", "label"]],
        on = "url",
        how = "inner",
        suffixes = ("_lexical", "_ssl")
    )

    mismatches = (
        label_check["label_lexical"] != label_check["label_ssl"]
    ).sum()
    
    print(
        f"[INFO] Label mismatches: {mismatches}"
    )

    if mismatches > 0:
        print(
            "[WARNING] Some URLs have different labels"
            "between datasets."
        )


if "label" in ssl_df.columns:
    ssl_df = ssl_df.drop(
        columns = ["label"]
    )

print("[INFO] Merging datasets...")

hybrid_df = pd.merge(
    lexical_df,
    ssl_df,
    on="url",
    how = "left"
)


#SSL/TLS Coverage 
ssl_check_column = "https"

if ssl_check_column in hybrid_df.columns:

    missing_ssl = (
        hybrid_df[ssl_check_column]
        .isna()
        .sum()
    )

    print(
        f"[INFO] URLs without SSL/TLS features: "
        f"{missing_ssl}"
    )

print("\n[INFO] Missing SSL/TLS values:")
print(
    hybrid_df[
        ["https", "issuer", "days_until_empty"]
    ].isna().sum()
)

print(
    f"[INFO] Hybrid rows: "
    f"{len(hybrid_df)}"
)

hybrid_df.to_csv(
    OUTPUT_DATASET,
    index = False
)

print(
    f"[SUCCESS] Hybrid dataset saved to: "
    f"{OUTPUT_DATASET}"
)

print(
    f"[SUCCESS] Total rows: "
    f"{len(hybrid_df)}"
)

print(
    f"[SUCCESS] Total columns: "
    f"{len(hybrid_df.columns)}"
)

print("\n[INFO] Hybrid Dataset Columns: ")

for col in hybrid_df.columns:
    print(col)