import requests
import re
import socket
import os
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()
console = Console()

KICKBOX_KEY   = os.getenv("KICKBOX_KEY", "")
RAPIDAPI_KEY  = os.getenv("RAPIDAPI_KEY", "")

def email_recon(email):
    results = []
    results.append(f"\n[bold cyan][+] Email Target: {email}[/bold cyan]\n")

    # 1. Basic validation
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        results.append("[red][!] Invalid email format[/red]")
        return "\n".join(results)

    domain = email.split('@')[1]
    results.append(f"[green][✓] Domain:[/green] {domain}")

    # 2. DNS check
    try:
        ip = socket.gethostbyname(domain)
        results.append(f"[green][✓] Domain resolves to:[/green] {ip}")
    except:
        results.append("[red][!] Domain does not resolve — possibly fake[/red]")

    # 3. Kickbox disposable check
    if KICKBOX_KEY:
        try:
            r = requests.get(
                f"https://open.kickbox.com/v1/disposable/{domain}",
                timeout=5
            )
            if r.status_code == 200:
                disposable = r.json().get('disposable', False)
                if disposable:
                    results.append("[red][!] DISPOSABLE email detected![/red]")
                else:
                    results.append("[green][✓] Not a disposable email[/green]")
        except:
            results.append("[yellow][?] Kickbox check failed[/yellow]")
    else:
        results.append("[yellow][?] KICKBOX_KEY not set — skipping disposable check[/yellow]")

    # 4. BreachDirectory via RapidAPI
    results.append("\n[bold][+] Breach Check:[/bold]")
    if RAPIDAPI_KEY:
        try:
            url = "https://breachdirectory.p.rapidapi.com/"
            headers = {
                "X-RapidAPI-Key": RAPIDAPI_KEY,
                "X-RapidAPI-Host": "breachdirectory.p.rapidapi.com"
            }
            params = {"func": "auto", "term": email}
            r = requests.get(url, headers=headers, params=params, timeout=8)
            if r.status_code == 200:
                data = r.json()
                if data.get("found"):
                    results.append(f"[red][!] Found in {data.get('result', []).__len__()} breach(es)![/red]")
                    for breach in data.get("result", [])[:5]:
                        results.append(f"    [red]- {breach}[/red]")
                else:
                    results.append("[green][✓] Not found in any breaches[/green]")
            else:
                results.append(f"[yellow][?] API returned: {r.status_code}[/yellow]")
        except Exception as e:
            results.append(f"[yellow][?] BreachDirectory error: {e}[/yellow]")
    else:
        results.append("[yellow][?] RAPIDAPI_KEY not set — skipping breach check[/yellow]")

    return "\n".join(results)
