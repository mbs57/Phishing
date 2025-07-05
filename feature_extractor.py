import re
import socket
import ssl
import requests
import tldextract
import whois
from urllib.parse import urlparse, urljoin
from datetime import datetime
from bs4 import BeautifulSoup
import logging
import numpy as np

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# API keys (replace with valid keys)
GOOGLE_API_KEY = "AIzaSyBdbKjpNBvY4DsvAEMNTuco1OtiqyeGhEY"  # Get from https://console.developers.google.com/
OPENPAGERANK_API_KEY = "c84gg084ko80gko0sg4w0sowsskwk8go8s04wc8c"


# Feature names as per UCI dataset
FEATURE_NAMES = [
    "Using the IP Address",
    "Long URL",
    "URL Shortening Services",
    "URL having @ Symbol",
    "Redirecting using //",
    "Prefix/Suffix with - in Domain",
    "Sub Domain and Multi Sub Domains",
    "HTTPS",
    "Domain Registration Length",
    "Favicon",
    "Non-Standard Port",
    "HTTPS Token in Domain",
    "Request URL",
    "URL of Anchor",
    "Links in Meta/Script/Link Tags",
    "Server Form Handler (SFH)",
    "Submitting to Email",
    "Abnormal URL",
    "Website Forwarding",
    "Status Bar Customization",
    "Disabling Right Click",
    "Using Pop-up Window",
    "IFrame Redirection",
    "Age of Domain",
    "DNS Record",
    "Website Traffic",
    "PageRank",
    "Google Index",
    "Number of Links Pointing to Page",
    "Statistical-Reports Based Feature"
]

def check_google_safe_browsing(url):
    """Check if URL is listed in Google Safe Browsing."""
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        payload = {
            "client": {"clientId": "phishing-detector", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = requests.post(api_url, json=payload, timeout=5)
        result = 1 if response.status_code == 200 and response.json().get("matches") else -1
        logging.debug(f"Google Safe Browsing for {url}: {result}")
        return result
    except Exception as e:
        logging.error(f"Google Safe Browsing error: {e}")
        return 1  # Default to phishing as per original

def get_pagerank(domain):
    """Check PageRank using OpenPageRank API."""
    try:
        headers = {'API-OPR': OPENPAGERANK_API_KEY}
        pagerank_url = f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}"
        response = requests.get(pagerank_url, headers=headers, timeout=5)
        data = response.json()
        rank = float(data['response'][0]['page_rank_decimal']) / 10  # Convert to 0-1 scale
        result = 1 if rank <= 0.2 else -1
        logging.debug(f"PageRank for {domain}: {result}")
        return result
    except Exception as e:
        logging.error(f"PageRank error: {e}")
        return 1  # Default to phishing as per original

def get_traffic_rank(domain):
    """Placeholder for website traffic (replacing Alexa API)."""
    try:
        # Optional: Implement Similarweb DigitalRank API
        # api_key = "YOUR_SIMILARWEB_API_KEY"
        # api_url = f"https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}"
        # response = requests.get(api_url, timeout=5)
        # data = response.json()
        # rank = data.get('similar_rank', {}).get('global_rank', 1000000)
        # result = -1 if rank < 100000 else 0 if rank < 1000000 else 1
        logging.warning("Traffic rank check not implemented. Returning neutral.")
        return 0  # Neutral to avoid bias
    except Exception as e:
        logging.error(f"Traffic rank error: {e}")
        return 0

def get_backlinks(domain):
    """Placeholder for backlink count."""
    try:
        # Optional: Implement Ahrefs or SEMrush API
        # api_key = "YOUR_AHREFS_API_KEY"
        # api_url = f"https://api.ahrefs.com/v1/sites/{domain}/backlinks"
        # response = requests.get(api_url, headers={'Authorization': f'Bearer {api_key}'}, timeout=5)
        # data = response.json()
        # backlinks = data.get('backlinks_count', 0)
        # result = -1 if backlinks > 100 else 0 if backlinks > 10 else 1
        logging.warning("Backlink check not implemented. Returning neutral.")
        return 0  # Neutral to avoid bias
    except Exception as e:
        logging.error(f"Backlink error: {e}")
        return 0

def extract_features(url):
    """Extract 30 phishing website features as per UCI dataset."""
    features = []
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ''
    domain = f"{ext.domain}.{ext.suffix}"
    subdomain = ext.subdomain
    path = parsed.path
    protocol = parsed.scheme

    # Initialize variables
    ssl_flag = 0
    ssl_age = 0
    cert_duration = 0
    reg_length = 0
    age_days = 0
    cert = {}
    html = ""
    soup = None

    # 1. Using the IP Address
    try:
        socket.inet_aton(hostname)
        hex_ip = bool(re.match(r'^0x[0-9A-Fa-f]+\.', hostname))
        result = 1 if socket.inet_aton(hostname) or hex_ip else -1
        features.append(result)
        logging.debug(f"Feature 1 (IP Address): {result}")
    except:
        features.append(-1)
        logging.debug("Feature 1 (IP Address): -1")

    # 2. Long URL
    result = 1 if len(url) >= 54 else -1
    features.append(result)
    logging.debug(f"Feature 2 (Long URL): {result}")

    # 3. URL Shortening Services
    shortening = r"bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co|is\.gd|buff\.ly|adf\.ly"
    result = 1 if re.search(shortening, url, re.IGNORECASE) else -1
    features.append(result)
    logging.debug(f"Feature 3 (Shortening Services): {result}")

    # 4. URL’s having “@” Symbol
    result = 1 if "@" in url else -1
    features.append(result)
    logging.debug(f"Feature 4 (@ Symbol): {result}")

    # 5. Redirecting using “//”
    if protocol == "http" and url.find("//", 7) != -1:
        result = 1
    elif protocol == "https" and url.find("//", 8) != -1:
        result = 1
    else:
        result = -1
    features.append(result)
    logging.debug(f"Feature 5 (// Redirect): {result}")

    # 6. Adding Prefix or Suffix Separated by (-)
    result = 1 if '-' in ext.domain else -1
    features.append(result)
    logging.debug(f"Feature 6 (Dash in Domain): {result}")

    # 7. Sub Domain and Multi Sub Domains
    # >2 dots → phishing (-1), 2 dots → suspicious (0), ≤1 dot → legitimate (1)
    clean_domain = subdomain.replace("www.", "") if subdomain else ""
    dot_count = clean_domain.count('.')
    result = -1 if dot_count > 2 else 0 if dot_count == 2 else 1
    features.append(result)
    logging.debug(f"Feature 7 (Subdomains): {result}")

    # SSL and WHOIS data
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                ssl_flag = 1
                valid_to = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                valid_from = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
                ssl_age = (valid_to - datetime.utcnow()).days
                cert_duration = (valid_to - valid_from).days
    except Exception as e:
        logging.error(f"SSL check error: {e}")
        ssl_flag = 0
        cert_duration = 0

    # 8. HTTPS (with issuer and cert age ≥ 2 years)
    trusted_issuers = ['geotrust', 'godaddy', 'network solutions', 'thawte', 'comodo', 'doster', 'verisign', "let's encrypt", 'digicert', 'globalsign', 'sectigo']
    issuer_valid = False
    try:
        issuer = cert.get('issuer', '')
        issuer_str = str(issuer).lower()
        issuer_valid = any(t in issuer_str for t in trusted_issuers)
    except:
        issuer_valid = False
    result = 1 if ssl_flag and issuer_valid and cert_duration >= 730 else -1
    features.append(result)
    logging.debug(f"Feature 8 (HTTPS): {result}")

    # 9. Domain Registration Length
    try:
        whois_data = whois.whois(domain)
        creation_date = whois_data.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        reg_length = (datetime.now() - creation_date).days
        age_days = reg_length
        result = 1 if reg_length >= 365 else -1
        features.append(result)
        logging.debug(f"Feature 9 (Domain Registration): {result}")
    except Exception as e:
        logging.error(f"WHOIS error: {e}")
        features.append(-1)
        logging.debug(f"Feature 9 (Domain Registration): -1")

    # 10. Favicon
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
        icon_link = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
        icon_url = icon_link['href'] if icon_link else ''
        if icon_url:
            icon_url = urljoin(url, icon_url)
            icon_domain = tldextract.extract(icon_url).registered_domain
            result = 1 if icon_domain and icon_domain != ext.registered_domain else -1
        else:
            result = 1  # No favicon is suspicious
        features.append(result)
        logging.debug(f"Feature 10 (Favicon): {result}")
    except Exception as e:
        features.append(1)
        logging.error(f"Favicon error: {e}")

    # 11. Non-Standard Port
    port = parsed.port
    result = 1 if port and port not in [80, 443] else -1
    features.append(result)
    logging.debug(f"Feature 11 (Non-Standard Port): {result}")

    # 12. HTTPS Token in Domain
    result = 1 if 'https' in ext.domain.lower() else -1
    features.append(result)
    logging.debug(f"Feature 12 (HTTPS in Domain): {result}")

    # 13. Request URL
    try:
        external = 0
        total = 0
        for tag in soup.find_all(['img', 'video', 'audio']):
            src = tag.get('src')
            if src:
                total += 1
                src_url = urljoin(url, src)
                src_domain = tldextract.extract(src_url).registered_domain
                if src_domain and src_domain != ext.registered_domain:
                    external += 1
        result = 1 if total and external / total > 0.5 else -1
        features.append(result)
        logging.debug(f"Feature 13 (Request URL): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 13 (Request URL): 1")

    # 14. URL of Anchor
    try:
        anchors = soup.find_all('a')
        bad_links = 0
        total = len(anchors)
        for a in anchors:
            href = a.get('href', '')
            if href and ('#' in href or 'javascript' in href.lower() or (href.startswith('http') and tldextract.extract(href).registered_domain != ext.registered_domain)):
                bad_links += 1
        result = 1 if total and bad_links / total > 0.5 else -1
        features.append(result)
        logging.debug(f"Feature 14 (Anchor URL): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 14 (Anchor URL): 1")

    # 15. Links in <Meta>, <Script>, <Link> Tags
    try:
        tags = soup.find_all(['meta', 'script', 'link'])
        external = 0
        total = 0
        for tag in tags:
            for attr in ['href', 'src']:
                val = tag.get(attr)
                if val:
                    total += 1
                    val_url = urljoin(url, val)
                    val_domain = tldextract.extract(val_url).registered_domain
                    if val_domain and val_domain != ext.registered_domain:
                        external += 1
        result = 1 if external > 0 else -1
        features.append(result)
        logging.debug(f"Feature 15 (Meta/Script/Link Tags): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 15 (Meta/Script/Link Tags): 1")

    # 16. Server Form Handler (SFH)
    try:
        forms = soup.find_all('form')
        sfh_found = any(form.get('action') in ['', 'about:blank'] or (form.get('action') and tldextract.extract(urljoin(url, form.get('action'))).registered_domain != ext.registered_domain) for form in forms)
        result = 1 if sfh_found else -1
        features.append(result)
        logging.debug(f"Feature 16 (SFH): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 16 (SFH): 1")

    # 17. Submitting to Email
    try:
        forms = soup.find_all('form')
        mailto_found = any('mailto:' in form.get('action', '').lower() or 'mail(' in form.get('action', '').lower() for form in forms)
        result = 1 if mailto_found else -1
        features.append(result)
        logging.debug(f"Feature 17 (Email Submission): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 17 (Email Submission): 1")

    # 18. Abnormal URL
    try:
        whois_domain = whois_data.domain_name
        if isinstance(whois_domain, list):
            whois_domain = whois_domain[0]
        result = -1 if whois_domain and whois_domain.lower() == domain.lower() else 1
        features.append(result)
        logging.debug(f"Feature 18 (Abnormal URL): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 18 (Abnormal URL): 1")

    # 19. Website Forwarding
    try:
        resp = requests.get(url, timeout=5, allow_redirects=True)
        result = 1 if len(resp.history) >= 4 else -1
        features.append(result)
        logging.debug(f"Feature 19 (Website Forwarding): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 19 (Website Forwarding): 1")

    # 20. Status Bar Customization
    try:
        scripts = soup.find_all('script')
        status_mod = any('window.status' in script.get_text().lower() or 'onmouseover' in script.get_text().lower() for script in scripts)
        result = 1 if status_mod else -1
        features.append(result)
        logging.debug(f"Feature 20 (Status Bar): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 20 (Status Bar): 1")

    # 21. Disabling Right Click
    try:
        result = 1 if 'event.button==2' in html.lower() or 'contextmenu' in html.lower() else -1
        features.append(result)
        logging.debug(f"Feature 21 (Right Click Disable): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 21 (Right Click Disable): 1")

    # 22. Using Pop-up Window
    try:
        scripts = soup.find_all('script')
        popup = any('window.open' in script.get_text().lower() for script in scripts)
        forms = soup.find_all('form')
        popup_form = any(form.get('action') for form in forms) if popup else False
        result = 1 if popup and popup_form else -1
        features.append(result)
        logging.debug(f"Feature 22 (Pop-up): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 22 (Pop-up): 1")

    # 23. IFrame Redirection
    try:
        iframes = soup.find_all('iframe')
        iframe_border = any(iframe.get('frameBorder', '0') == '0' for iframe in iframes)
        result = 1 if iframe_border else -1
        features.append(result)
        logging.debug(f"Feature 23 (Iframe): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 23 (Iframe): 1")

    # 24. Age of Domain
    result = 1 if age_days >= 180 else -1
    features.append(result)
    logging.debug(f"Feature 24 (Domain Age): {result}")

    # 25. DNS Record
    try:
        socket.gethostbyname(hostname)
        result = -1
        features.append(result)
        logging.debug(f"Feature 25 (DNS Record): {result}")
    except:
        result = 1
        features.append(result)
        logging.debug(f"Feature 25 (DNS Record): {result}")

    # 26. Website Traffic
    result = get_traffic_rank(domain)
    features.append(result)
    logging.debug(f"Feature 26 (Website Traffic): {result}")

    # 27. PageRank
    result = get_pagerank(domain)
    features.append(result)
    logging.debug(f"Feature 27 (PageRank): {result}")

    # 28. Google Index
    # Note: Consider using Google Custom Search API for production to avoid scraping issues
    try:
        google = f"https://www.google.com/search?q=site:{domain}"
        headers = {'User-Agent': 'Mozilla/5.0'}
        resp = requests.get(google, headers=headers, timeout=5)
        result = -1 if "did not match any documents" not in resp.text else 1
        features.append(result)
        logging.debug(f"Feature 28 (Google Index): {result}")
    except:
        features.append(1)
        logging.debug(f"Feature 28 (Google Index): 1")

    # 29. Number of Links Pointing to Page
    result = get_backlinks(domain)
    features.append(result)
    logging.debug(f"Feature 29 (Backlinks): {result}")

    # 30. Statistical-Reports Based Feature
    result = check_google_safe_browsing(url)
    features.append(result)
    logging.debug(f"Feature 30 (Statistical Reports): {result}")

    assert len(features) == 30, f"Expected 30 features, got {len(features)}"
    return np.array(features)

'''def extract_and_label_features(url):
    """Extract and label all 30 phishing features for a given URL."""
    try:
        features = extract_features(url)
        logging.info(f"Extracted features for {url}")
        
        print(f"\nFeature Extraction Results for: {url}")
        print("-" * 50)
        for i, (name, value) in enumerate(zip(FEATURE_NAMES, features), 1):
            status = "Phishing" if value == 1 else "Suspicious" if value == 0 else "Legitimate"
            print(f"Feature {i:2d}: {name:<40} -> {value:2d} ({status})")
        print(f"Total Features: {len(features)}")
        
        return features
    except Exception as e:
        logging.error(f"Error extracting features for {url}: {e}")
        return None'''

'''def main():
    """Test feature extraction with sample URLs."""
    test_urls = [
        "https://www.google.com",  # Legitimate
        "http://125.98.3.123/fake.html",  # Phishing (IP address)
        "http://bit.ly/19DXSk4",  # Phishing (short URL)
        "http://https-www-paypal-it-webapps-mpp-home.soft-hair.com"  # Phishing (HTTPS in domain)
    ]
    
    for url in test_urls:
        features = extract_and_label_features(url)
        if features is not None:
            logging.info(f"Feature vector: {features.tolist()}")

if __name__ == "__main__":
    main()'''