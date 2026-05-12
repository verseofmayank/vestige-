import requests
import os
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()
console = Console()

NUMVERIFY_KEY = os.getenv("NUMVERIFY_KEY", "")

def phone_recon(phone):
    results = []
    results.append(f"\n[bold cyan][+] Phone Target: {phone}[/bold cyan]\n")

    phone_clean = ''.join(c for c in phone if c.isdigit())

    if len(phone_clean) < 7:
        results.append("[red][!] Invalid phone number[/red]")
        return "\n".join(results)

    results.append(f"[green][✓] Cleaned:[/green] +{phone_clean}")
    results.append(f"[green][✓] Length:[/green]  {len(phone_clean)} digits")

    # Country code guess (basic)
    if phone_clean.startswith('1'):
        results.append("[green][✓] Country Code:[/green] +1 (USA/Canada)")
    elif phone_clean.startswith('91'):
        results.append("[green][✓] Country Code:[/green] +91 (India)")
    elif phone_clean.startswith('44'):
        results.append("[green][✓] Country Code:[/green] +44 (UK)")
    else:
        results.append("[yellow][?] Country Code:[/yellow] Unknown")

    # NumVerify lookup
    results.append("\n[bold][+] Carrier Lookup (NumVerify):[/bold]")
    if NUMVERIFY_KEY:
        try:
            r = requests.get(
                f"http://apilayer.net/api/validate",
                params={
                    "access_key": NUMVERIFY_KEY,
                    "number": phone_clean,
                    "format": 1
                },
                timeout=6
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("valid"):
                    results.append(f"[green][✓] Valid:[/green]          {d.get('valid')}")
                    results.append(f"[green][✓] Country:[/green]        {d.get('country_name','N/A')}")
                    results.append(f"[green][✓] Carrier:[/green]        {d.get('carrier','N/A')}")
                    results.append(f"[green][✓] Line Type:[/green]      {d.get('line_type','N/A')}")
                    results.append(f"[green][✓] Local Format:[/green]   {d.get('local_format','N/A')}")
                    results.append(f"[green][✓] Intl Format:[/green]    {d.get('international_format','N/A')}")
                else:
                    results.append("[red][!] Number is not valid[/red]")
        except Exception as e:
            results.append(f"[yellow][?] NumVerify error: {e}[/yellow]")
    else:
        results.append("[yellow][?] NUMVERIFY_KEY not set[/yellow]")

    return "\n".join(results)
