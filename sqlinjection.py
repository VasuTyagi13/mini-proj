import subprocess

# Specify the target URL for SQL injection testing
target_url = "localhost:3000"
# Replace the above URL with the actual vulnerable page URL

# Construct the SQLMap command
sqlmap_command = [
    "sqlmap",
    "-u",
    target_url,
    "--random-agent",
    "--level=2",
    "--risk=3",
    "--threads=5",
    "--batch",
    "--forms"
]

# Execute the SQLMap command using subprocess
process = subprocess.Popen(sqlmap_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = process.communicate()

# Check if the output indicates SQL injection vulnerability
output = stdout.decode()
if "is vulnerable to SQL injection" in output:
    print("The website is vulnerable to SQL injection.")
    # Extract vulnerable parameters, columns, and payload options
    vulnerable_parts = []
    lines = output.splitlines()
    for line in lines:
        if "Parameter:" in line or "Column:" in line or "Payload:" in line:
            vulnerable_parts.append(line.strip())
    if vulnerable_parts:
        print("Vulnerable parts:")
        for part in vulnerable_parts:
            print(part)
    else:
        print("No specific vulnerable parts identified.")
else:
    print("The website is not vulnerable to SQL injection.")
