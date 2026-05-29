from urllib.parse import urlparse

def url_from_page(page_url, limit = 20):
    '''Extracts URLs from a real webpage'''
    headers = {
        "User-Agent: "
    }
def analyze_url(url_list):
    '''Parses a list of URLs to extract the domain, protocol, and overall URL length. 
    This is a check for basic lexical feature extraction'''

   
        #parsing the URL into its core components 
    parsed_url = urlparse(url_list)

        #Extract the protocol (scheme) and domain (netloc)
    protocol = parsed_url.scheme if parsed_url.scheme else "None"
    domain = parsed_url.netloc if parsed_url.netloc else "No domain"
    url_length = len(url_list)

    https_exists = protocol == "https"

    return {
            "url" : url_list,
            "domain" : domain,
            "protocol" : protocol,
            "https" : https_exists,
            "length" : url_length
        }

def main():
    sample_urls = [
        "https://google.com",
        "https://www.wikipedia.org"
    ]

    print (f"{'URL':<43} | {'Domain':<25} | {'Protocol':<8} | {'HTTPS': <6}")
    print("-" * 90)

    for url in sample_urls:
        result = analyze_url(url)
        print(f"{result['url']:<43} | "
              f"{result['domain']:<25} | "
              f"{result['protocol']:<8} | "
              f"{str(result['https']):<6} | "
              f"{result['length']:<8}")


if __name__ == "__main__":
    #Test dataset mimicking both safe and phishing site's structures
    main()