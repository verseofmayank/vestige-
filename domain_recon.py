import socket
import requests
import subprocess
from rich.console import Console
from dotenv import load_dotenv

load_dotenv()
console = Console()

def domain_recon(domain):
    results = []
    results.append(f"\n[bold cyan][+] Domain Target: {domain}[/bold cyan]\n")

    # 1. DNS resolution
    try:
        ip = socket.gethostbyname(domain)
        results.append(f"[green][✓] Resolves to:[/green]   {ip}")
    except:
        results.append("[red][!] Could not resolve domain[/red]")
        return "\n".join(results)

    # 2. Reverse DNS
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        results.append(f"[green][✓] Reverse DNS:[/green]   {hostname}")
    except:
        results.append(f"[yellow][?] Reverse DNS:   Not available[/yellow]")

    # 3. IP GeoInfo
    try:
        r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.status_code == 200:
            d = r.json()
            results.append(f"[green][✓] Country:[/green]       {d.get('country_name','N/A')}")
            results.append(f"[green][✓] City:[/green]          {d.get('city','N/A')}")
            results.append(f"[green][✓] ISP/Org:[/green]       {d.get('org','N/A')}")
    except:
        results.append("[yellow][?] GeoIP lookup failed[/yellow]")

    # 4. HTTP Headers
    results.append("\n[bold][+] HTTP Headers:[/bold]")
    try:
        r = requests.get(f"https://{domain}", timeout=6,
                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
        results.append(f"[green][✓] Status Code:[/green]   {r.status_code}")
        results.append(f"[green][✓] Server:[/green]        {r.headers.get('Server','N/A')}")
        results.append(f"[green][✓] X-Powered-By:[/green]  {r.headers.get('X-Powered-By','N/A')}")
        results.append(f"[green][✓] Content-Type:[/green]  {r.headers.get('Content-Type','N/A')}")
        results.append(f"[green][✓] Final URL:[/green]     {r.url}")
    except:
        results.append("[yellow][?] Could not fetch HTTP headers[/yellow]")

    # 5. SSL Certificates via crt.sh
    results.append("\n[bold][+] SSL Certificates (crt.sh):[/bold]")
    try:
        r = requests.get(
            f"https://crt.sh/?q={domain}&output=json",
            headers={"User-Agent": "VESTIGE-OSINT"},
            timeout=12
        )
        if r.status_code == 200 and r.text.strip() and r.text.strip() != "null":
            certs = r.json()
            unique_subs = sorted({
                c.get('name_value', '').replace('*.', '')
                for c in certs
                if c.get('name_value')
            })
            results.append(f"[green][✓] Total certs found: {len(certs)}[/green]")
            results.append(f"[green][✓] Unique subdomains ({len(unique_subs)}):[/green]")
            for sub in unique_subs[:20]:
                results.append(f"    [cyan]- {sub}[/cyan]")
            if len(unique_subs) > 20:
                results.append(f"    [yellow]... +{len(unique_subs)-20} more[/yellow]")
        else:
            results.append("[yellow][?] No SSL certs found[/yellow]")
    except requests.Timeout:
        results.append("[yellow][?] crt.sh timed out — try again[/yellow]")
    except Exception as e:
        results.append(f"[yellow][?] SSL error: {e}[/yellow]")

    # 6. WHOIS via python-whois
    results.append("\n[bold][+] WHOIS Info:[/bold]")
    try:
        import whois
        w = whois.whois(domain)
        results.append(f"[green][✓] Registrar:[/green]     {w.registrar or 'N/A'}")
        results.append(f"[green][✓] Created:[/green]       {str(w.creation_date).split(' ')[0] if w.creation_date else 'N/A'}")
        results.append(f"[green][✓] Expires:[/green]       {str(w.expiration_date).split(' ')[0] if w.expiration_date else 'N/A'}")
        results.append(f"[green][✓] Updated:[/green]       {str(w.updated_date).split(' ')[0] if w.updated_date else 'N/A'}")
        ns = w.name_servers
        if ns:
            if isinstance(ns, list):
                for n in ns[:3]:
                    results.append(f"[green][✓] Nameserver:[/green]    {n}")
            else:
                results.append(f"[green][✓] Nameserver:[/green]    {ns}")
        results.append(f"[green][✓] Country:[/green]       {w.country or 'N/A'}")
    except ImportError:
        results.append("[yellow][?] Install: pip install python-whois --break-system-packages[/yellow]")
    except Exception as e:
        results.append(f"[yellow][?] WHOIS error: {e}[/yellow]")

    return "\n".join(results)

