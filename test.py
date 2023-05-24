import requests
from bs4 import BeautifulSoup

# Function to check for XSS vulnerability
def check_xss_vulnerability(url, payloads):
    # Make a GET request to the URL
    response = requests.get(url)

    # Parse the response content with BeautifulSoup
    soup = BeautifulSoup(response.content, 'html.parser')

    # Find all input and textarea tags in the HTML form
    input_tags = soup.find_all(['input', 'textarea'])

    # Check each input tag for XSS vulnerability
    for tag in input_tags:
        # Get the tag name and value attributes
        tag_name = tag.name
        tag_value = tag.get('value') or tag.text

        # Check if the tag value is vulnerable to XSS
        if tag_value:
            # Inject each payload into the tag value
            for payload in payloads:
                try:
                    payload_value = tag_value.replace('"', '\"').replace("'", "\'") + payload

                    # Send a POST request with the payload
                    if tag_name == 'input':
                        post_data = {tag.get('name'): payload_value}
                    elif tag_name == 'textarea':
                        tag.string = payload_value
                        post_data = {tag.get('name'): tag.text}
                    else:
                        continue

                    response = requests.post(url, data=post_data)

                    # Check if the payload is reflected in the response
                    if payload in response.text:
                        print(f'XSS vulnerability found in {tag_name} field with payload: {payload}!')
                except requests.exceptions.RequestException as e:
                    print(f'An error occurred while testing {tag_name} field with payload: {payload}')
                    print(f'Error: {e}')

# URL of the website to test
url = 'http://localhost:3000/#/login'

def read_file_lines(file_path):
    payloads = []
    with open(file_path, 'r', encoding="utf8") as file:
        for line in file:
            line = line.strip()
            payloads.append(line)
    return payloads

file_path = "xss_payloads.txt"#file path
payloads = read_file_lines(file_path)

# Call the function to check for XSS vulnerability
check_xss_vulnerability(url, payloads)
