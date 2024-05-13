# Import necessary libraries
import os
import re
import ssl
import whois
import socket
import requests
import ipaddress
import dns.resolver
from dotenv import load_dotenv
from rich.text import Text
from rich.live import Live
from rich.panel import Panel
from rich.console import Console
from formatting import console, display_whois, display_dns, display_ssl, display_dns, display_http_headers, display_geolocation, display_virustotal_results, display_abuseipdb_scan

console = Console()

# Load API keys from your .env file
load_dotenv('api_keys.env')
virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')

def is_valid_domain(domain):
    """Validate domain format using regular expression."""
    pattern = r'^([a-zA-Z0-9]+(-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,}$'
    return re.match(pattern, domain) is not None

def is_valid_ip(ip):
    """Validate IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def whois_lookup(domain):
    """Perform a WHOIS lookup for the given domain."""
    try:
        whois_data = whois.whois(domain)
        return dict(whois_data)  # Convert to dictionary
    except Exception as e:
        return {"Error": f"WHOIS lookup failed: {str(e)}"}

def dns_lookup(domain):
    """Perform a DNS lookup for the given domain to fetch various DNS records."""
    records = {}
    types_of_records = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT']
    
    for record_type in types_of_records:
        try:
            answers = dns.resolver.resolve(domain, record_type)
            records[record_type] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            records[record_type] = ["No records found"]
        except dns.resolver.NXDOMAIN:
            return {"Error": f"DNS lookup failed: Domain {domain} does not exist"}
        except dns.resolver.Timeout:
            return {"Error": "DNS query timed out"}
        except Exception as e:
            return {"Error": f"DNS lookup exception: {str(e)}"}

    return records

def ssl_cert_details(domain):
    """Retrieve SSL certificate details for the given domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                # Extract specific fields from the certificate
                subject = dict(x[0] for x in cert['subject'])
                issuer = dict(x[0] for x in cert['issuer'])

                cert_details = {
                    "Subject": subject.get('commonName', 'Not Available'),
                    "Issuer": issuer.get('organizationName', 'Not Available'),
                    "ASN1 Curve": cert.get('asn1Curve', 'Not Available'),
                    "NIST Curve": cert.get('nistCurve', 'Not Available'),
                    "Expires": cert['notAfter'],
                    "Renewed": cert['notBefore'],
                    "Serial Num": cert['serialNumber'],
                }
                return cert_details

    except Exception as e:
        return {"Error": f"SSL certificate retrieval failed: {str(e)}"}

def get_http_headers(url):
    """Fetch HTTP headers for a given URL, attempting HTTPS first, then falling back to HTTP if necessary."""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'
    }
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
        if response.headers:
            return dict(response.headers)  # Ensure headers are returned as a standard dictionary
        else:
            return {"Error": "No headers found"}
    except requests.exceptions.SSLError:
        try:
            url = url.replace('https://', 'http://') # Fallback to http
            response = requests.get(url, headers=headers, allow_redirects=True, timeout=10)
            if response.headers:
                return dict(response.headers)
            else:
                return {"Error": "No headers found after fallback to HTTP"}
        except requests.RequestException as e:
            return {"Error": f"HTTP request failed after fallback to HTTP: {str(e)}"}
    except requests.RequestException as e:
        return {"Error": f"HTTP request failed: {str(e)}"}

def get_geolocation(ip_or_domain):
    """Retrieve geolocation information for a given IP address or domain using ipinfo.io."""
    try:
        # Check if the input is a domain name and resolve it to an IP
        if not ip_or_domain.replace('.', '').isdigit():  # Simple check if it's an IP
            ip_or_domain = socket.gethostbyname(ip_or_domain)

        response = requests.get(f"https://ipinfo.io/{ip_or_domain}/json")
        if response.status_code == 200:
            return dict(response.json())  # Convert to dictionary
        else:
            return {"Error": f"Failed to retrieve data, status code: {response.status_code}"}
    except socket.gaierror:
        return {"Error": "DNS resolution failed, invalid domain"}
    except Exception as e:
        return {"Error": str(e)}

def virustotal_scan(url):
    """Check URL for malware and phishing using VirusTotal."""
    headers = {'x-apikey': virustotal_api_key}
    params = {'url': url, 'apikey': virustotal_api_key}
    response = requests.post('https://www.virustotal.com/api/v3/urls', data=params, headers=headers)
    report_url = response.json()["data"]["links"]["self"]
    report_response = requests.get(report_url, headers=headers)
    return report_response.json()["data"]["attributes"]

def abuseipdb_scan(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': ip,
        'maxAgeInDays': 90,
        'verbose': True  # This parameter should be set if detailed information is needed
    }
    headers = {
        'Accept': 'application/json',
        'Key': abuseipdb_api_key
    }
    response = requests.get(url, params=params, headers=headers)
    if response.status_code == 200:
        # print(response.json()['data'])
        return response.json()['data']
    else:
        return {"Error": f"Failed to retrieve data, status code: {response.status_code}"}

def main():
    # Welcome section
    welcome_text = "Welcome to Domain One View (DOV)!"
    description_text = ("DOV is an all-in-one tool for OSINT on a URL or IP. It performs various analyses and gathers information from multiple sources to provide a comprehensive view of a domain or IP address.")

    panel_content = Text(welcome_text, style="bold yellow", justify="center") + "\n" + Text(description_text, style="green")
    
    welcome_panel = Panel(
        panel_content,
        title="Domain One View",
        expand=False,
        border_style="bold magenta",
        padding=(1, 1),
        width=80,
    )
    console.print(welcome_panel, justify="center")
    console.print()  # Add an empty line for spacing

    while True:
        user_input = console.input("[bold magenta]Enter Domain Name or IP Address: [/bold magenta]")
        
        if is_valid_domain(user_input):
            domain = user_input
            break
        elif is_valid_ip(user_input):
            ip = user_input
            break
        else:
            console.print("[bold red]Invalid input. Please enter a valid domain name or IP address.[/bold red]")

    with Live(console=console, refresh_per_second=4, vertical_overflow="visible") as live:
        live.console.print("[grey50]Analyzing...[/grey50]")
        live.console.print()

        if 'domain' in locals():
            live.console.print("[green]Running WHOIS Lookup...[/green]")
            whois_data = whois_lookup(domain)
            display_whois(whois_data)
            live.console.print()

            live.console.print("[green]Running DNS Lookup...[/green]")
            dns_data = dns_lookup(domain)
            display_dns(dns_data)
            live.console.print()
            
            live.console.print("[green]Retrieving SSL Certificate Details...[/green]")
            ssl_data = ssl_cert_details(domain)
            display_ssl(ssl_data)
            live.console.print()
            
            live.console.print("[green]Running HTTP Header Analysis...[/green]")
            http_headers_data = get_http_headers(domain)
            display_http_headers(http_headers_data)
            live.console.print()
            
            live.console.print("[green]Running Geolocation...[/green]")
            geo_data = get_geolocation(domain)
            display_geolocation(geo_data)
            live.console.print()

            live.console.print("[green]Running VirusTotal Scan...[/green]")
            virustotal_data = virustotal_scan(domain)
            display_virustotal_results(virustotal_data)
            live.console.print()

        if 'ip' in locals():
            live.console.print("[green]Retrieving Geolocation Data...[/green]")
            geo_data = get_geolocation(ip)
            display_geolocation(geo_data)
            live.console.print()

            live.console.print("[green]Running AbuseIPDB Scan...[/green]")
            abuseipdb_data = abuseipdb_scan(ip)
            display_abuseipdb_scan(abuseipdb_data)
            live.console.print()

        live.console.print("[bold green]>>Analysis completed<<[/bold green]")

if __name__ == "__main__":
    main()