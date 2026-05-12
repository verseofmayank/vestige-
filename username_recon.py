import requests
import os
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.table import Table
from dotenv import load_dotenv

load_dotenv()
console = Console()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")

# Core platforms with error-string detection (more accurate)
PLATFORMS = {
    "GitHub":       {"url": "https://api.github.com/users/{}", "headers": {"Authorization": f"token {GITHUB_TOKEN}"} if GITHUB_TOKEN else {}, "not_found": None},
    "Reddit":       {"url": "https://www.reddit.com/user/{}/about.json", "headers": {"User-Agent": "VESTIGE-OSINT"}, "not_found": "\"error\": 404"},
    "Instagram":    {"url": "https://www.instagram.com/{}/", "headers": {}, "not_found": "Page Not Found"},
    "Twitter":      {"url": "https://twitter.com/{}", "headers": {}, "not_found": "This account doesn't exist"},
    "TikTok":       {"url": "https://www.tiktok.com/@{}", "headers": {"User-Agent": "Mozilla/5.0"}, "not_found": "Couldn't find this account"},
    "YouTube":      {"url": "https://www.youtube.com/@{}", "headers": {}, "not_found": None},
    "LinkedIn":     {"url": "https://www.linkedin.com/in/{}/", "headers": {}, "not_found": None},
    "Pinterest":    {"url": "https://www.pinterest.com/{}/", "headers": {}, "not_found": "page not found"},
    "Twitch":       {"url": "https://www.twitch.tv/{}", "headers": {}, "not_found": None},
    "Steam":        {"url": "https://steamcommunity.com/id/{}", "headers": {}, "not_found": "The specified profile could not be found"},
    "HackerNews":   {"url": "https://hacker-news.firebaseio.com/v0/user/{}.json", "headers": {}, "not_found": "null"},
    "Dev.to":       {"url": "https://dev.to/{}", "headers": {}, "not_found": "404"},
    "Pastebin":     {"url": "https://pastebin.com/u/{}", "headers": {}, "not_found": "Not Found"},
    "GitLab":       {"url": "https://gitlab.com/{}", "headers": {}, "not_found": "404"},
    "Bitbucket":    {"url": "https://bitbucket.org/{}/", "headers": {}, "not_found": "404"},
    "Medium":       {"url": "https://medium.com/@{}", "headers": {}, "not_found": "404"},
    "Quora":        {"url": "https://www.quora.com/profile/{}", "headers": {}, "not_found": "404"},
    "Tumblr":       {"url": "https://{}.tumblr.com", "headers": {}, "not_found": "There's nothing here"},
    "Flickr":       {"url": "https://www.flickr.com/people/{}", "headers": {}, "not_found": "Page Not Found"},
    "Vimeo":        {"url": "https://vimeo.com/{}", "headers": {}, "not_found": "Page not found"},
    "SoundCloud":   {"url": "https://soundcloud.com/{}", "headers": {}, "not_found": "404"},
    "Spotify":      {"url": "https://open.spotify.com/user/{}", "headers": {}, "not_found": "404"},
    "LastFm":       {"url": "https://www.last.fm/user/{}", "headers": {}, "not_found": "404"},
    "Goodreads":    {"url": "https://www.goodreads.com/{}", "headers": {}, "not_found": "404"},
    "Kaggle":       {"url": "https://www.kaggle.com/{}", "headers": {}, "not_found": "404"},
    "HackerRank":   {"url": "https://www.hackerrank.com/{}", "headers": {}, "not_found": "404"},
    "LeetCode":     {"url": "https://leetcode.com/{}", "headers": {}, "not_found": "404"},
    "CodeChef":     {"url": "https://www.codechef.com/users/{}", "headers": {}, "not_found": "404"},
    "Codeforces":   {"url": "https://codeforces.com/profile/{}", "headers": {}, "not_found": "404"},
    "npm":          {"url": "https://www.npmjs.com/~{}", "headers": {}, "not_found": "404"},
    "PyPI":         {"url": "https://pypi.org/user/{}/", "headers": {}, "not_found": "404"},
    "DockerHub":    {"url": "https://hub.docker.com/u/{}", "headers": {}, "not_found": "404"},
    "Keybase":      {"url": "https://keybase.io/{}", "headers": {}, "not_found": "404"},
    "ProductHunt":  {"url": "https://www.producthunt.com/@{}", "headers": {}, "not_found": "404"},
    "AngelList":    {"url": "https://angel.co/{}", "headers": {}, "not_found": "404"},
    "Behance":      {"url": "https://www.behance.net/{}", "headers": {}, "not_found": "404"},
    "Dribbble":     {"url": "https://dribbble.com/{}", "headers": {}, "not_found": "404"},
    "Fiverr":       {"url": "https://www.fiverr.com/{}", "headers": {}, "not_found": "404"},
    "About.me":     {"url": "https://about.me/{}", "headers": {}, "not_found": "404"},
    "Gravatar":     {"url": "https://en.gravatar.com/{}", "headers": {}, "not_found": "404"},
    "Telegram":     {"url": "https://t.me/{}", "headers": {}, "not_found": "If you have Telegram"},
    "Mastodon":     {"url": "https://mastodon.social/@{}", "headers": {}, "not_found": "404"},
    "Trello":       {"url": "https://trello.com/{}", "headers": {}, "not_found": "404"},
    "Snapchat":     {"url": "https://www.snapchat.com/add/{}", "headers": {}, "not_found": "404"},
    "Slideshare":   {"url": "https://www.slideshare.net/{}", "headers": {}, "not_found": "404"},
    "ResearchGate": {"url": "https://www.researchgate.net/profile/{}", "headers": {}, "not_found": "404"},
    "Clubhouse":    {"url": "https://www.clubhouse.com/@{}", "headers": {}, "not_found": "404"},
}

def check_platform(name, info, username):
    try:
        url = info["url"].format(username)
        headers = {**info.get("headers", {}), "User-Agent": "Mozilla/5.0 (X11; Linux x86_64)"}
        r = requests.get(url, headers=headers, timeout=5, allow_redirects=True)

        not_found_str = info.get("not_found")

        if not_found_str and not_found_str.lower() in r.text.lower():
            return name, "Not Found", url
        if r.status_code in [200, 301, 302]:
            return name, "Found", url
        return name, "Not Found", url
    except:
        return name, "Error", ""

def username_recon(username):
    results = []
    results.append(f"\n[bold cyan][+] Username Target: {username}[/bold cyan]")
    results.append(f"[*] Searching {len(PLATFORMS)} platforms...\n")

    found = []
    not_found = []
    errors = []

    with ThreadPoolExecutor(max_workers=15) as executor:
        futures = {
            executor.submit(check_platform, name, info, username): name
            for name, info in PLATFORMS.items()
        }
        for future in as_completed(futures):
            name, status, url = future.result()
            if status == "Found":
                found.append((name, url))
            elif status == "Error":
                errors.append(name)
            else:
                not_found.append(name)

    # Print found first
    results.append("[bold green][ FOUND ][/bold green]")
    for name, url in sorted(found):
        results.append(f"  [green][✓] {name:<15}[/green] → {url}")

    results.append(f"\n[bold red][ NOT FOUND ][/bold red]")
    results.append(f"  [red]{', '.join(sorted(not_found))}[/red]")

    if errors:
        results.append(f"\n[yellow][?] Errors: {', '.join(errors)}[/yellow]")

    results.append(f"\n[bold green][+] Found on {len(found)}/{len(PLATFORMS)} platforms[/bold green]")
    return "\n".join(results)
