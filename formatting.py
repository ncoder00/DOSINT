from rich.console import Console
from rich.table import Table
from rich.text import Text

console = Console()

def display_whois(data):
    table = Table(title="WHOIS Lookup", title_style="bold yellow")
    table.add_column("Field", style="magenta", no_wrap=True)
    table.add_column("Value", style="cyan", no_wrap=True)
    if "Error" in data:
        table.add_row("Error", data["Error"])
    else:
        for key, value in data.items():
            table.add_row(key, str(value))
    console.print(table)

def display_dns(data):
    console.print(Text("DNS Lookup", style="bold yellow"))
    if "Error" in data:
        console.print(f"[bold red]Error:[/bold red] {data['Error']}")
    else:
        console.print(f"[bold green]IP Address:[/bold green] {data['IP Address']}")

def display_ssl(cert_details):
    table = Table(title="SSL Certificate Details", title_style="bold yellow")
    table.add_column("Field", style="magenta")
    table.add_column("Value", style="cyan")
    if "Error" in cert_details:
        table.add_row("Error", cert_details["Error"])
    else:
        for key, value in cert_details.items():
            table.add_row(key, str(value))
    console.print(table)

def display_ports(ports):
    table = Table(title="Port Scanning Results", title_style="bold yellow")
    table.add_column("Port", style="magenta")
    table.add_column("Status", style="green")
    for port, status in ports.items():
        table.add_row(str(port), status)
    console.print(table)

def display_http_headers(headers):
    table = Table(title="HTTP Header Analysis", title_style="bold yellow")
    table.add_column("Header", style="magenta")
    table.add_column("Value", style="cyan")
    if "Error" in headers:
        table.add_row("Error", headers["Error"])
    else:
        for key, value in headers.items():
            table.add_row(key, str(value))
    console.print(table)

def display_geolocation(geo_data):
    table = Table(title="Geolocation", title_style="bold yellow")
    table.add_column("Field", style="magenta")
    table.add_column("Value", style="cyan")
    if "Error" in geo_data:
        table.add_row("Error", geo_data["Error"])
    else:
        for key, value in geo_data.items():
            table.add_row(key, str(value))
    console.print(table)

def display_malware_phishing(data):
    console.print(Text("Malware and Phishing Detection Results", style="bold yellow"))
    if 'positives' in data and 'total' in data:
        console.print(f"Detected malicious content in {data['positives']} out of {data['total']} checks.")
    else:
        console.print("No malicious content detected.")
