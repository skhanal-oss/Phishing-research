import os
import ssl
import socket
import pandas as pd
import requests
import json
from datetime import datetime, timezone
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa


INPUT_FILE = r"data/merged_labeled.csv"
FEATURE_OUTPUT = "ssl_tls_features.csv"
ERROR_OUTPUT = "ssl_tls_errors.csv"
ISSUER_OUTPUT = "ssl_tls_issuer_dictionary.csv"
MAX_WORKERS = 5
SOCKET_TIMEOUT  = 8
CHECKPOINT_SIZE = 500
CT_CACHE = {}

class SSLTLSFeatureExtractor:
    def __init__(self):
        self.issuer_mapping = {}
        self.next_issuer_id = 1
        self.total_urls = 0
        self.successful_count = 0
        self.failed_count = 0
    def get_issuer_id(self, issuer_name):
        if issuer_name not in self.issuer_mapping:
            self.issuer_mapping[issuer_name] = self.next_issuer_id
            self.next_issuer_id += 1

        return self.issuer_mapping[issuer_name]
    @staticmethod
    def detect_https(url):
        parsed = urlparse(url)
        return int(parsed.scheme.lower() == "https")
    
    @staticmethod
    def get_domain(url):
        if not url.startswith(("https://", "http://")):
            url = "https://" + url
        parsed = urlparse(url)
        return parsed.hostname
    
    def retrieve_certificate(self,domain):
        context = ssl.create_default_context()
        with socket.create_connection(
            (domain, 443), 
            timeout=SOCKET_TIMEOUT
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname=domain
            ) as ssock:
                cert_der = ssock.getpeercert(binary_form=True)
                cert_dict = ssock.getpeercert()

                tls_version = ssock.version()

                cipher_suite = (
                    ssock.cipher()[0]
                    if ssock.cipher()
                    else "unknown"
                )

                try:
                    chain_length = len(
                        ssock.get_verified_chain()
                    )
                except Exception:
                    chain_length = -1

        cert = x509.load_der_x509_certificate(
            cert_der,
            default_backend()
        )

        return (
            cert, cert_dict, 
            tls_version, cipher_suite, chain_length)
    
    @staticmethod
    def extract_expiry_days(cert):
        expiry = cert.not_valid_after_utc
        now = datetime.now(timezone.utc)
        delta = (expiry - now).days
        return delta
    
    @staticmethod
    def extract_issuer(cert):
        issuer = cert.issuer.rfc4514_string()
        return issuer
    
    @staticmethod
    def is_self_signed(cert):
        return int(
            cert.issuer == cert.subject
        )
    
    @staticmethod
    def verify_domain_match(cert_dict, domain):
        try:
            ssl.match_hostname(
                cert_dict,
                domain
            )
            return 1
        except Exception:
            return 0
        
    @staticmethod    
    def cert_age_days(cert):
        return (
            datetime.now(timezone.utc)
            - cert.not_valid_before_utc
        ).days

    @staticmethod    
    def cert_validity_period(cert):
        return(
            cert.not_valid_after_utc -
            cert.not_valid_before_utc
        ).days
    

    @staticmethod
    def extract_sans(cert):
        try:
            ext = cert.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            )
            return ext.value.get_values_for_type(
                x509.DNSName
            )
        
        except Exception:
            return []

    @staticmethod    
    def wildcard_cert(sans):
        return int(
            any(
                s.startswith("*.")
                for s in sans
            )
        )
    
    @staticmethod
    def rsa_key_length(cert):
        try:
            key= cert.public_key()
            if isinstance(
                key,
                rsa.RSAPublicKey
            ):
                return key.key_size
        except Exception:
            pass
        return -1
    
    @staticmethod
    def signature_algorithm(cert):
        try:
            return cert.signature_hash_algorithm.name
        except Exception:
            return "unknown"
        
    def retrieve_certificate(self, domain):
        context = ssl.create_default_context()
        with socket.create_connection(
            (domain, 443),
            timeout = SOCKET_TIMEOUT
        ) as sock:
            with context.wrap_socket(
                sock,
                server_hostname = domain
            ) as ssock:
                cert_der = ssock.getpeercert(
                    binary_form=True
                )
                cert_dict = ssock.getpeercert()
                tls_version = ssock.version()
                cipher_suite = ssock.cipher()[0]
                try:
                    chain_length = len(
                        ssock.get_verified_chain()
                    )
                except:
                    chain_length = -1
        cert = x509.load_der_x509_certificate(
            cert_der,
            default_backend()
        )
        return (
            cert,
            cert_dict,
            tls_version,
            cipher_suite,
            chain_length
        )
        

    def ct_logged(self, domain):
        if domain in CT_CACHE:
            return CT_CACHE[domain]
        try:
            print(f"[CT] Checking {domain}")
            url = (
                f"https://crt.sh/"
                f"?q={domain}&output=json"
            )

            r = requests.get (
                url,
                timeout = 10
            )

            print(
                f"[CT] {domain}"
                f"Status = {r.status_code}"
            )

            if r.status_code == 200:
                data=r.json()
                result = 1 if len(data) > 0 else 0
                CT_CACHE[domain] = result
                return result
            return 0
        except Exception as e:
            print(f"[CT ERROR] {domain}: {e}")
            return -1
        
    @staticmethod
    def classify_error(e):
        msg = str(e).lower()
        if ("name or service not known" in msg
            or "nodename nor servname" in msg):
            return "dns_failure"
        if "timed out" in msg:
            return "ssl_timeout"
        if "certificate has expired" in msg:
            return "expired_certificate"
        if "connection refused" in msg:
            return "connection_refused"
        if "hostname mismatch" in msg:
            return "hostname_mismatch"
        if "self signed" in msg:
            return "self_signed_certificate"
        if "tlsv1 alert" in msg:
            return "tls_handshake_failure"
        return "unknown_error"
    
    def process_url(self, row):
        url = row["url"]
        label = row["label"]
        self.total_urls += 1
        print(f"[INFO] Processing: {url}")
 
        try:
            domain = self.get_domain(url)
            if not domain:
                raise ValueError("Invalid domain")
            else:
                print(f"Domain extracted: {domain}")

        
            print(f"Connecting to {domain}: 443")

            (cert,
             cert_dict,
             tls_version,
             cipher_suite,
             chain_length) = self.retrieve_certificate(domain)
            
            sans = self.extract_sans(cert)
            issuer = self.extract_issuer(cert)
            print(f"SUCCESS: {domain} | "
                  f"TLS = {tls_version} |"
                  f"Cipher = {cipher_suite}")

            result = {
                "url": url,
                "label": label,
                "https": self.detect_https(url),
                "days_until_expiry": self.extract_expiry_days(cert),
                "issuer": issuer,
                "issuer_id": self.get_issuer_id(issuer),
                "self_signed": self.is_self_signed(cert),
                "domain_cert_match": self.verify_domain_match(
                    cert_dict,
                    domain
                ),
                "cert_age_days": self.cert_age_days(cert),
                "cert_validity_period": self.cert_validity_period(cert),
                "num_SANs": len(sans),
                "wildcard_cert": self.wildcard_cert(sans),
                "rsa_key_length": self.rsa_key_length(cert),
                "signature_algorithm": self.signature_algorithm(cert),
                "tls_version": tls_version,
                "cipher_suite": cipher_suite,
                "cert_chain_length": chain_length,
                "ct_logged": self.ct_logged(domain)
            }

            self.successful_count += 1
            return result, None
        
        
        except Exception as e:
            print(
                f"[Error] {url} ->"
                f"{type(e).__name__}: {e}"
            )
            self.failed_count += 1
            error_record = {
                "url": url,
                "label": label,
                "error_type": self.classify_error(e),
                "error_message": str(e)
            }
            return None, error_record
    
        
    def process_chunk(self, chunk):
        features = []

        errors = []

        with ThreadPoolExecutor(
            max_workers = MAX_WORKERS
        ) as executor:
            futures = [
                executor.submit(
                    self.process_url,
                    row
                )
                for _, row in chunk.iterrows()
            ]

            for future in futures:

                result, error = future.result()
                if result:
                    features.append(result)
                if error:
                    errors.append(error)
        return features, errors
    
if __name__ == "__main__":
    extractor = SSLTLSFeatureExtractor()

    test_domain= "google.com"

    (
        cert,
        cert_dict,
        tls_version,
        cipher_suite,
        chain_length
    ) = extractor.retrieve_certificate(test_domain)

    print("TLS:", tls_version)
    print("Cipher:", cipher_suite)
    print("Issuer:", cert.issuer)

    reader = pd.read_csv(INPUT_FILE, chunksize = 5)
    first_chunk = next(reader)
    print(first_chunk["url"].head(10))

    reader = pd.read_csv(
        INPUT_FILE, 
        chunksize = CHECKPOINT_SIZE
    )

    chunk_num = 0
    for chunk in reader:
        chunk_num += 1
        print(
            f"\n======="
            f"CHUNK {chunk_num}"
            f"({len(chunk)} URLs)"
            f"========\n"
        )
        features, errors = extractor.process_chunk(chunk)
    
        print(
            f"[CHUNK {chunk_num}]"
            f"Success = {len(features)}"
            f"Failed = {len(errors)}"
        )
        if features:
            pd.DataFrame(features).to_csv(
                FEATURE_OUTPUT,
                mode = "a",
                header = not os.path.exists(FEATURE_OUTPUT),
                index = False
            )
        if errors:
            pd.DataFrame(errors).to_csv(
                ERROR_OUTPUT,
                mode = "a",
                header = not os.path.exists(ERROR_OUTPUT),
                index = False
            )

    issuer_df = pd.DataFrame(

        [
            (v,k)
            for k, v in 
            extractor.issuer_mapping.items()
        ],

        columns=[
            "issuer_id",
            "issuer_name"
        ]
    )

    issuer_df.to_csv(
        ISSUER_OUTPUT,
        index = False
    )
    summary = {
        "total_urls":
        extractor.total_urls,
        "successful_tls_extractions":
        extractor.successful_count,
        "failed_tls_extractions":
        extractor.failed_count,
        "unique_issuers":
        len(extractor.issuer_mapping)
    }

    with open(
        "ssl_tls_summary.json",
        "w"
    ) as f:
        json.dump(
            summary, 
            f,
            indent = 4
        )

    print("SSL/TLS Feature Extraction Completed.")

    if os.path.exists(ERROR_OUTPUT):
        err_df = pd.read_csv(ERROR_OUTPUT)
        print("\nError Summary:")
        print(err_df["error_type"].value_counts())
        print("\nSample Errors:")
        print(err_df["error_message"].head(20))

        