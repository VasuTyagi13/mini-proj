import requests

# Function to check for potential DoS vulnerabilities
def check_dos_vulnerability(url):
    x = 0
    try:
        # Perform an HTTP GET request to the website
        response = requests.get(url)

        # Check the response status code
        if response.status_code >= 500:
            print(f"The website '{url}' is returning a server error (status code: {response.status_code}). It may be vulnerable to DoS attacks.")
            x+=1

        # Check the response time
        response_time = response.elapsed.total_seconds()
        if response_time > 5:
            print(f"The website '{url}' has a high response time ({response_time} seconds). It may be vulnerable to DoS attacks.")
            x+=1

        # Check the content length
        content_length = len(response.content)
        if content_length > 1024 * 1024:
            print(f"The website '{url}' has a large content size ({content_length} bytes). It may be vulnerable to DoS attacks.")
            x+=1

    except requests.exceptions.RequestException as e:
        print(f"Failed to connect to '{url}': {str(e)}")
        x+=1
    except Exception as e:
        print(f"An error occurred while checking DoS vulnerability for '{url}': {str(e)}")
        x+=1

    if x==0:
        print("Website is protected from DOS attacks.")

# Example usage
target_url = "https://cnn.com"
check_dos_vulnerability(target_url)
input()
