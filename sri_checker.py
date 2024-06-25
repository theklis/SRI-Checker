from bs4 import BeautifulSoup
import re, sys, requests, hashlib, base64

#  For each URL, the scanner should fetch the HTML content.
def get_html_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error in fetching {url} - {e}")
        return None

#  Identify all script/link tags that should contain SRI hashes.
def get_scripts_links(html):
    print(f"Parsing html content...")
    parsed_html = BeautifulSoup(html, 'html.parser')
    scripts = parsed_html.find_all('script', src=True)
    links = parsed_html.find_all('link', href=True, rel='stylesheet')
    return scripts, links

def download_resource(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.content
    except requests.exceptions.RequestException as e:
        print(f"Error fetching resource {url} - {e}")
        return None

def calculate_sri_hash(content, algo):
    if algo == 'sha256':
        hash_func = hashlib.sha256()
    elif algo == 'sha384':
        hash_func = hashlib.sha384()
    elif algo == 'sha512':
        hash_func = hashlib.sha512()
    else: 
        #usupported
        return None
    hash_func.update(content)
    return base64.b64encode(hash_func.digest()).decode('utf-8')


#  Check if each identified tag has a valid SRI hash.
def check_for_sri(tag, attribute):
    integrity = tag.get('integrity')
    if not integrity:
        return False, "Missing SRI hash"
    
    #e.g. sha256-<hash>
    algo, hash_value = integrity.split('-')
    expected_hash = hash_value.strip()
    # sha256_pattern = r'sha256-[A-Za-z0-9+/=]{43}=$'
    # sha384_pattern = r'sha384-[A-Za-z0-9+/=]{64}$'
    # sha512_pattern = r'sha512-[A-Za-z0-9+/=]{86}==$'
    
    resource_url = tag.get(attribute, 'unknown')
    if resource_url == 'unknown':
        return False, f"Missing {attribute} attribute"

    resource_content = download_resource(resource_url)
    if resource_content is None:
        return False, f"Failed to download resource from {resource_url}"

    calculated_hash = calculate_sri_hash(resource_content, algo)
    #print(f"This is the calculated hash: {calculated_hash} for {resource_url} and this is the expected hash: {expected_hash}")
    if calculated_hash is None:
        return False, f"Unsupported hash algorithm: {algo}"
    
    if calculated_hash != expected_hash:
        return False, "Calculated hash does not match expected hash!"
    
    return True, "Valid SRI hash"

# The scanner should accept a list of URLs as input.
def check_urls(urls):
    for url in urls:
        print(f"Checking {url}")
        html = get_html_content(url)
        if not html:
            continue
        scripts, links = get_scripts_links(html)

        #  Report any tags with missing or invalid SRI hashes.
        for script_tag in scripts:
            valid, message = check_for_sri(script_tag, 'src')
            if not valid:
                src = script_tag.get('src','unknown')
                print(f"<script> - {message}: {src}")

        for link_tag in links:
            valid, message = check_for_sri(link_tag, 'href')
            if not valid:
                href = link_tag.get('href','unknown')
                print(f"<link> - {message}: {href}")

def check_urls_from_args():
    if len(sys.argv) < 2:
        print("Usage: python sri_checker.py <url1> <url2> <url3>")
        return
    urls = sys.argv[1:]
    check_urls(urls)

if __name__ == "__main__":
    check_urls_from_args()
