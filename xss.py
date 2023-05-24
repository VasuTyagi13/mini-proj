import requests
from bs4 import BeautifulSoup

def read_file_lines(file_path):
    payloads = []
    with open(file_path, 'r', encoding="utf8") as file:
        for line in file:
            line = line.strip()
            payloads.append(line)
    return payloads

file_path = "xss_payloads.txt"#file path
payloads = read_file_lines(file_path)
payload = '<h1>vasu</h1>'

def check_xss_vulnerability(url):
    # for payload in payloads:
    response = requests.get(url)
    soup = BeautifulSoup(requests.get(url).content, 'html.parser')
    print(soup)
    if payload in soup:
        print(f"XSS Vulnerability Detected!\nPayload: {payload}\n\n")

# Example usage
url = "http://localhost:3000/#/search?q=<h1>vasu<%2Fh1>"
check_xss_vulnerability(url)
