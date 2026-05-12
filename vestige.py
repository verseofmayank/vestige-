import click
from rich.console import Console
from banner import show_banner
from email_recon import email_recon
from domain_recon import domain_recon
from ip_recon import ip_recon
from username_recon import username_recon
from phone_recon import phone_recon

console = Console()
CTX = dict(help_option_names=['-h', '--help'])

@click.group(context_settings=CTX)
@click.pass_context
def cli(ctx):
    """
    \b
    VESTIGE — Digital Footprint Discovery Tool
    by mayhack | Traces Left Behind...

    \b
    Usage Examples:
      python vestige.py email -e target@gmail.com
      python vestige.py domain -d example.com
      python vestige.py ip -i 8.8.8.8
      python vestige.py username -u targetuser
      python vestige.py phone -p +919876543210
    """
    if ctx.invoked_subcommand is not None:
        show_banner()

@cli.command(context_settings=CTX)
@click.option('--email', '-e', required=True, help='Target email address')
def email(email):
    """Email recon — breach check, disposable detection"""
    console.print(email_recon(email))

@cli.command(context_settings=CTX)
@click.option('--domain', '-d', required=True, help='Target domain (e.g. example.com)')
def domain(domain):
    """Domain recon — DNS, subdomains, SSL certs"""
    console.print(domain_recon(domain))

@cli.command(context_settings=CTX)
@click.option('--ip', '-i', required=True, help='Target IP address')
def ip(ip):
    """IP recon — GeoIP, ISP, abuse score"""
    console.print(ip_recon(ip))

@cli.command(context_settings=CTX)
@click.option('--username', '-u', required=True, help='Target username')
def username(username):
    """Username recon — search across 13+ platforms"""
    console.print(username_recon(username))

@cli.command(context_settings=CTX)
@click.option('--phone', '-p', required=True, help='Target phone (e.g. +919876543210)')
def phone(phone):
    """Phone recon — carrier, country, line type"""
    console.print(phone_recon(phone))

if __name__ == '__main__':
    cli()
