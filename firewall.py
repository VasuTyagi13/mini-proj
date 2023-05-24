import socket

# Define the allowed and blocked IP addresses, ports, and packets
allowed_ips = ["192.168.0.1", "10.0.0.2"]
blocked_ips = ["192.168.0.2"]
allowed_ports = [80, 443]
blocked_ports = [8080]
allowed_packets = ["GET", "POST"]
blocked_packets = ["PUT", "DELETE"]

def firewall(ip, port, packet):
    # Check if the IP address is allowed or blocked
    if ip in blocked_ips:
        return False
    if ip not in allowed_ips:
        return False

    # Check if the port is allowed or blocked
    if port in blocked_ports:
        return False
    if port not in allowed_ports:
        return False

    # Check if the packet is allowed or blocked
    if packet in blocked_packets:
        return False
    if packet not in allowed_packets:
        return False

    # If all checks pass, the packet is allowed
    return True

# Example usage
def process_packet(ip, port, packet):
    if firewall(ip, port, packet):
        print("Packet allowed")
        # Process the packet
    else:
        print("Packet blocked")

# Test cases
process_packet("192.168.0.1", 80, "GET")  # Allowed
process_packet("192.168.0.2", 80, "GET")  # Blocked
process_packet("192.168.0.1", 8080, "GET")  # Blocked
