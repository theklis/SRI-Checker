from bs4 import BeautifulSoup
import re, sys, requests

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

#  Check if each identified tag has a valid SRI hash.
def check_for_sri(tag):
    integrity = tag.get('integrity')
    if not integrity:
        return False, "Missing SRI hash"
    regPattern = r'sha(256|384|512)-[A-Za-z0-9+/=]+'
    if not re.match(regPattern, integrity):
        return False, "Invalid SRI hash"
    return True, "Valid SRI hash"

def check_urls_from_args():
    if len(sys.argv) < 2:
        print("Usage: python sri_checker.py <url1> <url2> <url3>")
        return
    urls = sys.argv[1:]  # The first argument is the script name, so skip it
    check_urls(urls)

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
            valid, message = check_for_sri(script_tag)
            if not valid:
                src = script_tag.get('src','unknown')
                print(f"<script> - {message}: {src}")

        for link_tag in links:
            valid, message = check_for_sri(link_tag)
            if not valid:
                href = link_tag.get('href','unknown')
                print(f"<link> - {message}: {href}")

if __name__ == "__main__":
    check_urls_from_args()
    # testurl = """
    #         <html>
    #         <head>
    #             <title>Example Domain</title>
    #             <link rel="stylesheet" href="styles.css" crossorigin="anonymous">
    #         </head>
    #         <body>
    #             <h1>Hello, world!</h1>
    #             <script src="script.js" integrity="sha26-def456" crossorigin="anonymous"></script>
    #         </body>
    #         </html>
    # """
    # #html = get_html_content(testurl)
    # print(f"This is the html after get_html_content: {testurl}")
    # scripts, links = get_scripts_links(testurl)
    # print(f"these are the links: {links}")
    # print(f"these are the scripts: {scripts}")
    # for script_tag in scripts:
    #     valid, message = check_for_sri(script_tag)
    #     if not valid:
    #         print(f"{message}: <script> tag {script_tag}")

    # for link_tag in links:
    #     valid, message = check_for_sri(link_tag)
    #     if not valid:
    #         print(f"{message}: <link> tag {link_tag}")
