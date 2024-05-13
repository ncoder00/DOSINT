from rich.console import Console
from rich.table import Table
from rich.text import Text

# Create a console object for output
console = Console()

# Common styles for reuse across display functions
styles = {
    "title": "bold yellow",
    "header": "magenta",
    "data": "cyan",
    "error": "bold red",
    "success": "bold green",
    "neutral": "grey50"
}

def display_whois(data):
    """
    Display the WHOIS lookup results in a formatted table, including detailed domain information.
    
    Parameters:
    data (dict): WHOIS data to display.
    """
    table = Table(title="Domain Whois", title_style=styles["title"])
    table.add_column("Field", style=styles["header"], no_wrap=True)
    table.add_column("Value", style=styles["data"], no_wrap=True)

    # Helper function to handle list values and convert them to a comma-separated string
    def list_to_string(value):
        if isinstance(value, list):
            return ', '.join(str(v) for v in value if v) if value else "Not Available"
        return str(value) if value is not None else "Not Available"

    # Common fields to display with handling for multiple statuses and name servers
    fields = [
        ("Domain Name", "domain_name"),
        ("Registry Domain ID", "registry_domain_id"),
        ("Registrar WHOIS Server", "whois_server"),
        ("Registrar URL", "registrar_url"),
        ("Updated Date", "updated_date"),
        ("Creation Date", "creation_date"),
        ("Registry Expiry Date", "expiry_date"),
        ("Registrar", "registrar"),
        ("Registrar IANA ID", "registrar_iana_id"),
        ("Registrar Abuse Contact Email", "registrar_abuse_contact_email"),
        ("Registrar Abuse Contact Phone", "registrar_abuse_contact_phone"),
        ("Last update of whois database", "last_updated")
    ]

    for field, key in fields:
        value = data.get(key)  # Retrieve value using key
        table.add_row(field, list_to_string(value))  # Convert list to string if necessary

    # Special handling for multiple domain statuses and name servers
    domain_statuses = data.get("domain_status", [])
    if domain_statuses:
        status_str = list_to_string(domain_statuses)
        table.add_row("Domain Status", status_str)

    name_servers = data.get("name_servers", [])
    if name_servers:
        servers_str = list_to_string(name_servers)
        table.add_row("Name Server", servers_str)

    console.print(table)

def display_dns(data):
    """
    Display DNS lookup results including A, AAAA, CNAME, NS, MX, and TXT records in a formatted table.
    
    Parameters:
    data (dict): DNS data to display, expected to contain lists of records for A, AAAA, CNAME, NS, MX, and TXT types.
    """
    table = Table(title="DNS Records", title_style=styles["title"])
    table.add_column("Type", style=styles["header"])
    table.add_column("Record", style=styles["data"])

    # Helper function to handle list values and convert them to a comma-separated string
    def list_to_string(value):
        if isinstance(value, list):
            # Check if the list contains 'No records found' as its only element
            if len(value) == 1 and value[0] == "No records found":
                return "No records found"
            return ', '.join(v.strip() for v in value)  # Remove any trailing periods from DNS records
        return str(value) if value is not None else "Not Available"

    # Define the types of records we are expecting
    record_types = ["A", "AAAA", "CNAME", "NS", "MX", "TXT"]

    for record_type in record_types:
        records = data.get(record_type, [])  # Fetch records for each type
        if records:
            records_str = list_to_string(records)
            table.add_row(record_type, records_str)
        else:
            table.add_row(record_type, "Not Available")  # Handle the case where no records are found

    console.print(table)

def display_ssl(cert_details):
    """
    Display SSL certificate details in a formatted table.
    
    Parameters:
    cert_details (dict): SSL certificate details to display.
    """
    table = Table(title="SSL Certificate", title_style=styles["title"])
    table.add_column("Field", style=styles["header"])
    table.add_column("Detail", style=styles["data"])

    if 'Error' in cert_details:
        table.add_row('Error', cert_details['Error'])
    else:
        for field, detail in cert_details.items():
            table.add_row(field, detail)

    console.print(table)

def display_http_headers(headers):
    """
    Display HTTP headers in a formatted table.
    
    Parameters:
    headers (dict or requests.structures.CaseInsensitiveDict): HTTP headers to display.
    """
    table = Table(title="HTTP Header Analysis", title_style=styles["title"])
    table.add_column("Header", style=styles["header"])
    table.add_column("Value", style=styles["data"])

    # Check if headers are empty or an error was passed
    if headers and not isinstance(headers, dict):
        table.add_row("Error", "No headers found or invalid header format.")
    elif headers:
        for key, value in headers.items():
            # Ensuring value is a string and handling potentially long values
            if isinstance(value, list):
                value = ', '.join(value)  # Join lists into a single string
            wrapped_value = '\n'.join(value[i:i+80] for i in range(0, len(value), 80))
            table.add_row(key, wrapped_value)
    else:
        table.add_row("Error", "No headers found")

    console.print(table)

def display_geolocation(geo_info):
    """Display geolocation information in a formatted table."""
    console = Console()
    table = Table(title="Geolocation Information", title_style=styles["title"])

    table.add_column("Property", style=styles["header"])
    table.add_column("Value", style=styles["data"])

    if "Error" in geo_info:
        table.add_row("Error", geo_info["Error"])
    else:
        for key, value in geo_info.items():
            table.add_row(key, str(value))

    console.print(table)

def display_virustotal_results(data):
    console.print(Text("VirusTotal Scan", style="bold yellow"))
    
    if isinstance(data, dict):
        stats = data.get('stats', {})
        results = data.get('results', {})

        if stats and results:
            table = Table(title="VirusTotal Scan Results", title_style="bold yellow")
            table.add_column("Engine", style="magenta")
            table.add_column("Category", style="cyan")
            table.add_column("Result", style="green")

            # Prepare to sort and truncate the results based on the "Result" column
            priority_results = []
            other_results = []

            for engine, result in results.items():
                if result['result'] != 'clean' and result['result'] != 'unrated':
                    priority_results.append((engine, result))
                else:
                    other_results.append((engine, result))
            
            # Sort priority results (non-clean/unrated)
            priority_results.sort(key=lambda x: (x[1]['result'] == 'malicious', x[0]), reverse=True)

            # Sort and truncate other results (clean/unrated)
            other_results.sort(key=lambda x: x[0])
            other_results = other_results[:10]  # Only take the top 10 clean/unrated results

            final_results = priority_results + other_results  # Combine the lists

            for engine, result in final_results:
                category_text = Text(result['category'])
                result_text = Text(result['result'])

                if result['category'] == 'malicious':
                    category_text.stylize("bold red")
                    result_text.stylize("bold red")
                elif result['category'] == 'harmless':
                    category_text.stylize("green")
                    result_text.stylize("green")
                elif result['category'] == 'undetected':
                    category_text.stylize("grey50")
                    result_text.stylize("grey50")
                else:
                    category_text.stylize("bold yellow")
                    result_text.stylize("bold yellow")

                table.add_row(engine, category_text, result_text)

            console.print(table)

            console.print("\nScan Statistics:")
            for category, count in stats.items():
                console.print(f"{category.capitalize()}: {count}")
        else:
            console.print("Incomplete data received from VirusTotal.")
    else:
        console.print("[bold red]Error: Failed to retrieve VirusTotal data[/bold red]")

def display_abuseipdb_scan(data):
    """
    Display AbuseIPDB scan results in a formatted table, including the top 10 latest abuse reports.
    """
    if 'Error' in data:
        console.print(f"[bold red]{data['Error']}[/bold red]")
        return

    # Display summary information
    console.print("\nIP Abuse Reports for {0}:".format(data.get('ipAddress', 'N/A')))
    console.print("This IP address has been reported a total of {0} times from {1} distinct sources.".format(data.get('totalReports', 'N/A'), data.get('numDistinctUsers', 'N/A')))
    console.print("{0} was first reported on {1}, and the most recent report was {2}.".format(data.get('ipAddress', 'N/A'), data.get('firstReportedAt', 'N/A'), data.get('lastReportedAt', 'N/A')))
    console.print("Recent Reports: We have received reports of abusive activity from this IP address within the last week. It is potentially still actively engaged in abusive activities. Reference for AbuseIPDB report categories 'https://www.abuseipdb.com/categories'")

    # Setup table for detailed reports if available
    if 'reports' in data:
        report_table = Table(show_header=True, header_style="bold magenta")
        report_table.add_column("Reporter", style="dim", justify="right")
        report_table.add_column("IoA Timestamp")
        report_table.add_column("Comment")
        report_table.add_column("Categories")

        # Sort the reports by the 'reportedAt' field and slice the top 10
        sorted_reports = sorted(data['reports'], key=lambda x: x['reportedAt'], reverse=True)[:10]

        # Loop over each report and add it to the table
        for report in sorted_reports:
            categories = ', '.join(str(cat) for cat in report.get('categories', []))
            report_table.add_row(str(report.get('reporterId', 'N/A')), report.get('reportedAt', 'N/A'), report.get('comment', 'N/A'), categories)

        console.print(report_table)
    else:
        console.print("[bold red]No detailed reports available.[/bold red]")
