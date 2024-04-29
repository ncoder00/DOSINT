import os
import whois 
import socket
import ssl
import requests
from formatting import display_whois, display_dns, display_ssl, display_ports, display_http_headers, display_geolocation, display_malware_phishing, console
from dotenv import load_dotenv

# Load the API key from your .env file
load_dotenv('api_keys.env')
virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')

def whois_lookup(domain):
    try:
        w = whois.whois(domain)
        return dict(w)  # Convert to dictionary
    except Exception as e:
        return {"Error": str(e)}  # Return error as dictionary

def dns_lookup(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return {"IP Address": ip_address}  # Return as dictionary
    except socket.gaierror:
        return {"Error": "DNS Lookup failed: Hostname could not be resolved"}
    except Exception as e:
        return {"Error": str(e)}

def ssl_cert_details(domain):
    try:
        hostname = domain
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return dict(cert)  # Convert to dictionary directly
    except Exception as e:
        return {"Error": str(e)}

def port_scanning(domain):
    results = {}
    ports = [22, 80, 443]  # You can expand this list
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((domain, port))
        status = "Open" if result == 0 else "Closed"
        results[port] = status
    return results

def http_header_analysis(domain):
    try:
        response = requests.get(f"http://{domain}")
        return dict(response.headers)  # Convert headers to dictionary
    except requests.RequestException as e:
        return {"Error": str(e)}

def geolocation(domain):
    try:
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        return dict(response.json())  # Convert to dictionary
    except Exception as e:
        return {"Error": str(e)}

def check_malware_phishing(url):
    """Check URL for malware and phishing using VirusTotal."""
    headers = {'x-apikey': virustotal_api_key}
    params = {'url': url, 'apikey': virustotal_api_key}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params, headers=headers)
    report_response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params, headers=headers)
    return report_response.json()

def main():
    domain = console.input("[bold magenta]Enter Domain Name: [/bold magenta]")
    whois_data = whois_lookup(domain)
    dns_data = dns_lookup(domain)
    ssl_data = ssl_cert_details(domain)
    ports_data = port_scanning(domain)
    http_headers_data = http_header_analysis(domain)
    geo_data = geolocation(domain)
    malware_phishing_data = check_malware_phishing(domain)

    display_whois(whois_data)
    display_dns(dns_data)
    display_ssl(ssl_data)
    display_ports(ports_data)
    display_http_headers(http_headers_data)
    display_geolocation(geo_data)
    display_malware_phishing(malware_phishing_data)

if __name__ == "__main__":
    main()
