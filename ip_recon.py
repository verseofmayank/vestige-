import requests
import os
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()
console = Console()

ABUSEIPDB_KEY = os.getenv("ABUSEIPDB_KEY", "")

def ip_recon(ip):
    results = []
    results.append(f"\n[bold cyan][+] IP Target: {ip}[/bold cyan]\n")

    # 1. GeoIP — free, no key needed
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            d = r.json()
            results.append(f"[green][✓] Country:[/green]     {d.get('country_name','N/A')}")
            results.append(f"[green][✓] City:[/green]        {d.get('city','N/A')}")
            results.append(f"[green][✓] Region:[/green]      {d.get('region','N/A')}")
            results.append(f"[green][✓] ISP/Org:[/green]     {d.get('org','N/A')}")
            results.append(f"[green][✓] Timezone:[/green]    {d.get('timezone','N/A')}")
            results.append(f"[green][✓] Coordinates:[/green] {d.get('latitude','N/A')}, {d.get('longitude','N/A')}")
        else:
            results.append("[yellow][?] GeoIP lookup failed[/yellow]")
    except:
        results.append("[red][!] Could not fetch GeoIP data[/red]")

    # 2. AbuseIPDB reputation
    results.append("\n[bold][+] Reputation Check:[/bold]")
    if ABUSEIPDB_KEY:
        try:
            headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json"}
            params  = {"ipAddress": ip, "maxAgeInDays": "90"}
            r = requests.get("https://api.abuseipdb.com/api/v2/check",
                             headers=headers, params=params, timeout=5)
            if r.status_code == 200:
                d = r.json().get("data", {})
                score = d.get("abuseConfidenceScore", 0)
                color = "red" if score > 50 else "yellow" if score > 10 else "green"
                results.append(f"[{color}][✓] Abuse Score: {score}/100[/{color}]")
                results.append(f"[green][✓] Total Reports: {d.get('totalReports','N/A')}[/green]")
                results.append(f"[green][✓] Last Reported: {d.get('lastReportedAt','Never')}[/green]")
        except Exception as e:
            results.append(f"[yellow][?] AbuseIPDB error: {e}[/yellow]")
    else:
        results.append("[yellow][?] ABUSEIPDB_KEY not set — skipping reputation check[/yellow]")

    return "\n".join(results)
