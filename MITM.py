import requests
from urllib.parse import urlparse
import dns.resolver

# Function to check if a website is vulnerable to MitM attacks
def check_mitm_vulnerability(url):
    # Verify if the website supports HTTPS
    if not url.startswith("https://"):
        print(f"[-] The website '{url}' is not using HTTPS. It may be vulnerable to MitM attacks.")
    else:
        print("[+] Website has HTTPS.")

    # Check for HSTS header
    response = requests.get(url)
    if "strict-transport-security" not in response.headers:
        print(f"[-] The website '{url}' does not have HSTS (HTTP Strict Transport Security) enabled. It may be vulnerable to MitM attacks.")
    else:
        print("[+] Website has HSTS (HTTP Strict Transport Security) enabled.")

    # Check for certificate expiration
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.split(":")[0]
    try:
        cert = requests.get(f"https://crt.sh/?q={domain}&output=json").json()
        if cert and "not_after" in cert[0]:
            expiration_date = cert[0]["not_after"]
            print(f"[-] The SSL/TLS certificate for '{domain}' will expire on {expiration_date}. It may be vulnerable to MitM attacks if not renewed.")
    except Exception as e:
        print(f"[#] Failed to check certificate expiration for '{domain}': {str(e)}")

    # Check for vulnerable SSL/TLS protocols and ciphers
    try:
        response = requests.get(url)
        if response.history and any("https://" in r.url for r in response.history):
            print(f"[-] The website '{url}' has insecure SSL/TLS configuration. It may be vulnerable to MitM attacks.")
        else:
            print(f"[+] The website '{url}' has secure SSL/TLS configuration.")
    except requests.exceptions.SSLError:
        print(f"[-] The website '{url}' has SSL/TLS configuration issues. It may be vulnerable to MitM attacks.")

    # Check for HTTP security headers
    security_headers = ["x-frame-options", "x-xss-protection", "x-content-type-options", "content-security-policy"]
    for header in security_headers:
        if header not in response.headers:
            print(f"[-] The website '{url}' is missing the '{header}' security header.")

    # Check for insecure cookie attributes
    cookies = response.cookies
    for cookie in cookies:
        if not cookie.secure:
            print(f"[-] The cookie '{cookie.name}' in the website '{url}' is not marked as secure.")

    # Check for vulnerable session management
    if "set-cookie" in response.headers:
        cookie_value = response.headers["set-cookie"]
        if "httponly" not in cookie_value.lower():
            print(f"[-] The session cookie in the website '{url}' does not have the 'HttpOnly' flag. It may be vulnerable to session hijacking attacks.")
        else:
            print(f"[+] The session cookie in the website '{url}' has the 'HttpOnly' flag.")

    # Check for DNS-based MitM attacks
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.split(":")[0]

        dns_resolver = dns.resolver.Resolver()
        answers = dns_resolver.resolve(domain, "A")
        resolved_ips = [str(answer) for answer in answers]

        # Check if the resolved IP addresses are empty or None
        if not resolved_ips:
            print(f"[-] DNS resolution for '{domain}' failed. The website may be vulnerable to DNS-based MitM attacks.")
        elif response.raw._connection.sock.getpeername()[0] not in resolved_ips:
            print(f"[-] The DNS resolution for '{domain}' does not match the website's IP. It may be vulnerable to DNS-based MitM attacks.")
        else:
            print(f"[+] The the resolved IP addresses for '{domain}' not empty or None.")
    except dns.resolver.NXDOMAIN:
        print(f"[-] The domain '{domain}' does not exist.")
    except Exception as e:
        print(f"[#] Failed to perform DNS resolution for '{domain}': {str(e)}")


   # Check for Certificate Transparency
    try:
        cert_transparency_url = f"https://www.gstatic.com/ct/log_list/v3/all_logs_list.json"
        logs_response = requests.get(cert_transparency_url)
        if logs_response.status_code == 200:
            logs = logs_response.json()
            for log in logs["logs"]:
                log_url = log["url"]
                response = requests.get(log_url)
                if response.status_code == 200 and domain in response.text:
                    print(f"[+] The website '{url}' is using a trusted Certificate Transparency log.")
                    break
            else:
                print(f"[-] The website '{url}' is not using a trusted Certificate Transparency log. It may be susceptible to unauthorized certificate issuance.")
        else:
            print(f"[#] Failed to retrieve the list of Certificate Transparency logs.")
    except Exception as e:
        print(f"[#] Failed to check Certificate Transparency for '{domain}': {str(e)}")

    # Check for Content Injection
    def check_content_injection(response):
        suspicious_keywords = ["<script>", "alert(", "eval(", "onmouseover="]

        for keyword in suspicious_keywords:
            if keyword.lower() in response.text.lower():
                print(f"[-] The website '{url}' contains potential content injection with keyword: '{keyword}'")

    # Perform a sample request to check for content injection
    try:
        response = requests.get(url)
        check_content_injection(response)
    except Exception as e:
        print(f"[#] Failed to perform a sample request to '{url}' for content injection check: {str(e)}")

    # Check for Web Application Firewall (WAF) Bypass
    def check_waf_bypass(response):
        # Implement WAF bypass detection logic
        if "Bypassed WAF Protection" in response.text:
            print(f"[-] The website '{url}' may have vulnerable WAF protections.")
        else:
            print(f"[+] The website '{url}' does not have vulnerable WAF protections.")

    # Perform a sample request to check for WAF bypass
    try:
        response = requests.get(url)
        check_waf_bypass(response)
    except Exception as e:
        print(f"[#] Failed to perform a sample request to '{url}' for WAF bypass check: {str(e)}")
    
target_url = "https://github.com"
check_mitm_vulnerability(target_url)