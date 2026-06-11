import pandas as pd
import numpy as np
import re
import math
import requests
import bz2
from urllib.parse import urlparse
from collections import Counter
import ipaddress
from math import log2

#PhishTank(phishing) dataset download

#PHISHTANK_API_KEY = "" #registration for application key temporarily disabled 

#PHISHTANK_URL = (
   # f"https://data.phishtank.com/data/"
   # f"{PHISHTANK_API_KEY}/online-valid.csv.bz2")
#print(PHISHTANK_API_KEY)
#print("Downloading latest PhishTank feed...")

#response = requests.get(PHISHTANK_URL, timeout = 120)
#response.raise_for_status()

#with open("online-valid.csv.bz2", "wb") as f:
 #   f.write(response.content)

#print("Download complete.")

#config

#INPUT_CSV = bz2.open(
 #   "online-valid.csv.bz2",
  #  mode="rt",
   # encoding="utf-8",
    #errors = "ignore"
#)
 
INPUT_CSV = "data\merged_labeled.csv" 
OUTPUT_CSV = "lexical_features.csv"
URL_COLUMN = "url"
LABEL_COLUMN = "label"
CHUNK_SIZE = 100000

SUSPICIOUS_KEYWORDS = [
    "login",
    "secure",
    "verify",
    "account",
    "update",
    "banking",
    "password",
    "signin",
    "authenticate",
    "confirm",
    "billing",
    "invoice",
    "payment",
    "bank"
]

def shannon_entropy(text):
    if not text:
        return 0.0
    counts = Counter(text)

    length = len(text)

    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def is_ip_address(hostname):
    try:
        ipaddress.ip_address(hostname)
        return 1
    except:
        return 0
    

def count_subdomains(hostname):
    if not hostname:
        return 0 
    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0 
    
    return len(parts) - 2

def get_tld(hostname):
    if not hostname:
        return ""
    parts = hostname.split(".")
    return parts[-1] if len(parts) > 1 else ""

def extract_features(url):

    if pd.isna(url):
        url = ""

    url = str(url).strip()
    lower_url = url.lower()

    parsed = urlparse(url if "://" in url else "https://" + url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    #Length Features
    url_length = len(url)
    hostname_length = len(hostname)
    path_length = len(path)

    #Individual Character Features
    dot_count = url.count(".")
    dash_count = url.count("-")
    underscore_count = url.count("_")
    slash_count = url.count("/")
    question_count = url.count("?")
    equal_count = url.count("=")
    ampersand_count = url.count("&")
    percent_count = url.count("%")
    at_count = url.count("@")
    hash_count = url.count("#")
    plus_count = url.count("+")

    digits = sum(c.isdigit() for c in url)
    letters = sum(c.isalpha() for c in url)
    uppercase = sum(c.isupper() for c in url)
    lowercase = sum(c.islower() for c in url)

    special_chars = sum(
        not c.isalnum()
        for c in url
    )

    digit_ratio = digits / url_length if url_length else 0
    letter_ratio = letters / url_length if url_length else 0
    special_ratio = special_chars / url_length if url_length else 0
    
    #Domain features
    if hostname:
        parts = hostname.split(".")
        if len(parts) >= 2:
            tld = parts[-1]
            subdomain_count = max(len(parts) - 2, 0)
        else:
            tld = "" 
            subdomain_count = 0

    else:
        tld = ""
        subdomain_count = 0

    has_ip = is_ip_address(hostname)


    #Structural features
    path_depth = len(
        [x for x in path.split("/") if x]
    )

    query_param_count  = (
        query.count("&") + 1
        if query else 0 
    )

    has_https = (
        1 if parsed.scheme == "https"
        else 0
    )

    #Entropy
    url_entropy = shannon_entropy(lower_url)
    domain_entropy = shannon_entropy(hostname)


    #Binary suspicious features
    keyword_features = {}

    for word in SUSPICIOUS_KEYWORDS:
        keyword_features[f"kw_{word}"] = (
            1 if word in lower_url else 0
        )
    
    return {
        "url": url,

        "url_length": url_length,
        "hostname_length": hostname_length,
        "path_length": path_length,

        "digit_count": digits,
        "letter_count": letters,
        "uppercase_count": uppercase,
        "lowercase_count": lowercase,
        "special_symbol_count": special_chars,

        "digit_ratio": digit_ratio,
        "letter_ratio": letter_ratio,
        "special_ratio": special_ratio,

        "dot_count": dot_count,
        "dash_count": dash_count,
        "underscore_count": underscore_count,
        "slash_count": slash_count,
        "question_count": question_count,
        "equal_count": equal_count,
        "ampersand_count": ampersand_count,
        "percent_count": percent_count,
        "at_count": at_count,
        "hash_count": hash_count,
        "plus_count": plus_count,

        "subdomain_count": subdomain_count,
        "tld": tld,
        "ip_address_present": has_ip,

        "path_depth": path_depth,
        "query_param_count": query_param_count,
        "has_https": has_https,

        "url_entropy": url_entropy,
        "domain_entropy": domain_entropy,

        **keyword_features
    }


first_chunk = True


for chunk in pd.read_csv(
    INPUT_CSV,
    usecols = [URL_COLUMN, LABEL_COLUMN],
    chunksize = CHUNK_SIZE
):

    features_df = pd.DataFrame(chunk[URL_COLUMN].apply(extract_features).tolist())

    features_df["label"] = chunk[LABEL_COLUMN].values

    features_df.to_csv(
        OUTPUT_CSV,
        mode = "w" if first_chunk else "a",
        header = first_chunk,
        index = False
    )

    first_chunk = False

    print(f"Processed {len(features_df):,} URLs")

print("Feature extraction complete.")
print(f"Saved to: {OUTPUT_CSV}")




