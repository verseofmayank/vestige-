# VESTIGE - Digital Footprint Discovery Tool
**by mayhack**

Traces Left Behind...

## What is VESTIGE?

VESTIGE is a modular OSINT CLI tool that discovers digital footprints of targets across the internet. Search for emails, domains, IPs, usernames, and phone numbers with a single tool.

## Features

✓ Email Reconnaissance (breach check, linked accounts)
✓ Domain Reconnaissance (DNS, WHOIS, SSL certificates)
✓ IP Reconnaissance (GeoIP, ASN, reputation)
✓ Username Reconnaissance (100+ platform search)
✓ Phone Reconnaissance (carrier, country metadata)
✓ Color-coded terminal output
✓ Fast parallel searches

## Installation

### Requirements
- Python 3.10+
- pip

### Steps

1. Clone/Download this project
```bash
git clone https://github.com/yourusername/vestige.git
cd vestige
```

2. Install dependencies
```bash
pip install -r requirements.txt
```

3. Make executable (Linux/Mac)
```bash
chmod +x vestige.py
```

## Usage

### Show Help
```bash
python vestige.py help-cmd
```

### Email Reconnaissance
```bash
python vestige.py email --email target@example.com
```

### Domain Reconnaissance
```bash
python vestige.py domain --domain example.com
```

### IP Reconnaissance
```bash
python vestige.py ip --ip 8.8.8.8
```

### Username Reconnaissance
```bash
python vestige.py username --username targetuser
```

### Phone Reconnaissance
```bash
python vestige.py phone --phone +91-XXXXXXXXXX
```

## Module Details

| Module | Command | What it does |
|--------|---------|-------------|
| Email | `python vestige.py email --email <target>` | Finds breaches, linked accounts |
| Domain | `python vestige.py domain --domain <target>` | DNS records, SSL certs, WHOIS |
| IP | `python vestige.py ip --ip <target>` | GeoIP, ISP, coordinates |
| Username | `python vestige.py username --username <target>` | Searches 100+ social platforms |
| Phone | `python vestige.py phone --phone <target>` | Carrier info, country, metadata |

## Examples

```bash
# Investigate an email
python vestige.py email --email john.doe@example.com

# Check a domain
python vestige.py domain --domain google.com

# Lookup IP address
python vestige.py ip --ip 1.1.1.1

# Find username across platforms
python vestige.py username --username musk

# Analyze phone number
python vestige.py phone --phone +919876543210
```

## APIs Used

- HaveIBeenPwned (Breach check) - Free
- IPapi.co (GeoIP) - Free
- crt.sh (SSL certificates) - Free
- GitHub API - Free
- Reddit API - Free

## Output

All results are displayed in colored terminal output with structured formatting.

## Disclaimer

This tool is for educational and authorized security testing only. Unauthorized access to computer systems is illegal. Always get permission before investigating targets.

## Future Updates

- [ ] JSON/Markdown report generation
- [ ] AI-powered chaining mode
- [ ] Breach database integration
- [ ] Google Dork generator
- [ ] Wayback Machine integration
- [ ] Certificate transparency search

## License

MIT License

## Author

**mayhack**

---

*Traces Left Behind...*
