import csv
import os
import ssl
import socket 
import logging
import traceback
from datetime import datetime
from collections import Counter
from cryptography import x509 
from cryptography.hazmat.backends import default_backend
from rich.console import Console
from rich.table import Table

logging.basicConfig(
    filename = "cert_errors.log",
    level=logging.ERROR,
    format = "%(message)s",
    filemode = "w" 
)

INPUT_CSV = r"scripts\domains-top-500.csv"
OUTPUT_CSV = "certificate_results.csv"

print(f"Reading: {INPUT_CSV}")
print(os.path.exists(INPUT_CSV))
console = Console()

def classify_error(e: Exception) -> str:
    msg = str(e).lower()

    if isinstance(e, socket.gaierror):
        return "DNS_ERROR (domain not resolved)"
    
    if isinstance(e, socket.timeout):
        return "TIMEOUT"
    
    if isinstance(e, ssl.SSLError):
        return "SSL_ERROR"
    
    if "timed out" in msg:
        return "TIMEOUT"
    
    if "getaddrinfo" in msg:
        return "DNS_ERROR"
    
    if "certificate in msg":
        return "SSL_ERROR"
    
    return "UNKNOWN_ERROR"

error_counts = Counter()

def get_certificate_details(domain, timeout=5):
    result = {
        "domain": domain,
        "https": "",
        "issuer":"",
        "expires": "",
        "self_signed": "",
    }

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((domain, 443), timeout = timeout) as sock:
            with context.wrap_socket(sock, server_hostname = domain) as tls_sock:
                cert_der = tls_sock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(
            cert_der,
            default_backend()
        )

        issuer = cert.issuer.rfc4514_string()

        expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")

        self_signed = "Yes" if cert.issuer == cert.subject else "No"

        result.update({
            "https": "Yes",
            "issuer": issuer, 
            "expires": expiry,
            "self_signed": self_signed,
        })

    except Exception as e:
        error_type = classify_error(e)


        msg = f"[{error_type}] {domain} -> {e}"
        print(msg)
        logging.error(msg)

        result.update({
            "https": "No",
            "issuer": error_type,
            "expires": "",
            "self_signed":""
        })
        error_counts[error_type] += 1

    return result

results = []

with open(INPUT_CSV, newline="", encoding = "utf-8") as infile:
    reader = csv.DictReader(infile)

    for row in reader:
        domain = row["domain"].strip()

        if not domain:
            continue

        results.append(get_certificate_details(domain))

with open(OUTPUT_CSV, "w", newline="", encoding = "utf-8") as outfile:
    writer = csv.DictWriter(
        outfile, 
        fieldnames=[
            "domain",
            "https",
            "issuer",
            "expires",
            "self_signed",
        ],
    )

    writer.writeheader()
    writer.writerows(results)

table = Table(
    title = "TLS Certificate Assessment",
    show_lines = True
)

table.add_column("Domain", style = "cyan")
table.add_column("HTTPS", justify="center")
table.add_column("Self-Signed", justify="center")
table.add_column("Expires", justify = "center")
table.add_column("Issuer", style= "green")

for r in results:
    table.add_row(
        r["domain"],
        r["https"],
        r["self_signed"],
        r["expires"],
        r["issuer"],
    )

console.print(table)

console.print(
    f"\n✅ Scan Complete"
    f"({len(results)} domains processed)"
)
console.print(
    f"Output: {OUTPUT_CSV}"
)

print("\n Error Summary:")
for k, v in error_counts.items():
    print(k,v)

    