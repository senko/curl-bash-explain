"""Core logic: parse input, download scripts, call LLM."""

import ipaddress
import re
import logging
import socket
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from openai import OpenAI
from django.conf import settings

from .models import AnalysisCache

logger = logging.getLogger(__name__)

DOWNLOAD_TIMEOUT = 30
MAX_SCRIPT_SIZE = 512 * 1024  # 512 KB
MAX_REDIRECTS = 5


def _validate_url(url: str) -> None:
    """Block requests to private/internal IP ranges (SSRF protection)."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise AnalysisError(f"Invalid URL: {url}")

    # Resolve hostname to IP(s) and check each one
    try:
        addrinfos = socket.getaddrinfo(hostname, parsed.port or 80)
    except socket.gaierror:
        raise AnalysisError(f"Could not resolve hostname: {hostname}")

    for family, _, _, _, sockaddr in addrinfos:
        ip = ipaddress.ip_address(sockaddr[0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            raise AnalysisError(
                f"Requests to private/internal addresses are not allowed: {hostname}"
            )

# Patterns for extracting URLs from curl/wget pipe-to-bash commands
CURL_PIPE_RE = re.compile(
    r'(?:curl|wget)\s+'
    r'(?:[^|]*?\s)'
    r'["\']?(https?://[^\s"\'>|)]+)["\']?'
    r'(?:\s|\||$|[)"\'])',
)

URL_RE = re.compile(r"^https?://\S+$")


class AnalysisError(Exception):
    pass


def parse_input(raw: str) -> str:
    """
    Given user input, figure out the script URL.

    Accepts:
      - A plain URL (we'll scrape the page for an installer command)
      - A curl/wget pipe-to-bash command (extract the URL directly)
    """
    raw = raw.strip()
    if not raw:
        raise AnalysisError("Please enter a URL or a shell command.")

    # Case 1: looks like a curl/wget pipe command
    pipe_match = CURL_PIPE_RE.search(raw)
    if pipe_match:
        url = pipe_match.group(1).rstrip("'\"")
        logger.info("Extracted script URL from command: %s", url)
        return url

    # Case 2: plain URL — scrape the page for an installer command
    if URL_RE.match(raw):
        return _scrape_for_installer(raw)

    raise AnalysisError(
        "Could not understand the input. Please enter either a website URL "
        "or a shell command like: curl -fsSL https://example.com/install.sh | bash"
    )


def _safe_get(url: str, **kwargs) -> requests.Response:
    """Fetch a URL with SSRF protection and limited redirects."""
    _validate_url(url)
    kwargs.setdefault("timeout", DOWNLOAD_TIMEOUT)
    kwargs.setdefault("headers", {"User-Agent": "Mozilla/5.0 (compatible; curlbash-explain/1.0)"})
    kwargs["allow_redirects"] = False

    for _ in range(MAX_REDIRECTS):
        resp = requests.get(url, **kwargs)
        if resp.is_redirect or resp.is_permanent_redirect:
            url = resp.headers.get("Location", "")
            if not url:
                raise AnalysisError("Redirect with no Location header.")
            _validate_url(url)  # validate each redirect target
            continue
        resp.raise_for_status()
        return resp

    raise AnalysisError("Too many redirects.")


def _scrape_for_installer(page_url: str) -> str:
    """Scrape a webpage and look for curl|bash style commands."""
    try:
        resp = _safe_get(page_url)
    except requests.RequestException as exc:
        raise AnalysisError(f"Failed to fetch page {page_url}: {exc}")

    content_type = resp.headers.get("Content-Type", "")

    # If it's already a shell script, return the URL directly
    if (
        "text/x-shellscript" in content_type
        or "application/x-sh" in content_type
        or resp.text.lstrip().startswith("#!/")
    ):
        return page_url

    soup = BeautifulSoup(resp.text, "html.parser")
    # Look in <code>, <pre>, and elements with common class names
    candidates = []
    for tag in soup.find_all(["code", "pre", "span", "div", "p", "input", "textarea"]):
        text = tag.get_text() if tag.name not in ("input", "textarea") else tag.get("value", "")
        if not text:
            continue
        match = CURL_PIPE_RE.search(text)
        if match:
            candidates.append(match.group(1).rstrip("'\""))

    if not candidates:
        raise AnalysisError(
            f"Could not find an installer command (curl/wget piped to bash/sh) "
            f"on the page: {page_url}"
        )

    # Return the first match (most likely the main installer)
    logger.info("Scraped installer URL %s from %s", candidates[0], page_url)
    return candidates[0]


def download_script(url: str) -> str:
    """Download the shell script without executing it."""
    try:
        resp = _safe_get(url)
    except requests.RequestException as exc:
        raise AnalysisError(f"Failed to download script from {url}: {exc}")

    if len(resp.content) > MAX_SCRIPT_SIZE:
        raise AnalysisError(
            f"Script is too large ({len(resp.content) // 1024} KB). "
            f"Maximum supported size is {MAX_SCRIPT_SIZE // 1024} KB."
        )

    return resp.text


def analyze_script(script_content: str, script_url: str) -> str:
    """Use OpenAI to analyze the script and return Markdown explanation."""
    client = OpenAI(api_key=settings.OPENAI_API_KEY)

    prompt = f"""You are an expert shell script security analyst. A user wants to understand
what the following installer script does before they run it via `curl | bash`.

Analyze the script thoroughly and provide:

1. **Overview** — A brief summary of what the script does in plain language.
2. **Step-by-step breakdown** — Walk through the major sections/functions of the script.
3. **What it installs/modifies** — List files, directories, system services, PATH changes, etc.
4. **Network activity** — Any URLs it contacts, downloads, or data it sends.
5. **Permissions & privilege escalation** — Does it use sudo/root? What does it need elevated privileges for?
6. **Potential concerns** — Anything unusual, risky, or worth noting from a security perspective.
7. **Verdict** — A brief assessment: is this a standard, trustworthy installer, or are there red flags?

Be specific and cite line numbers or function names where relevant.
Format your response as clean Markdown.
Do NOT include any dates, timestamps, or version timeliness notes in your analysis.

Script URL: {script_url}

```bash
{script_content}
```"""

    try:
        response = client.responses.create(
            model=settings.OPENAI_MODEL,
            input=prompt,
        )
        return response.output_text
    except Exception as exc:
        raise AnalysisError(f"LLM analysis failed: {exc}")


def process_input(raw_input: str) -> dict:
    """
    Main entry point. Returns dict with keys:
      - script_url, script_content, explanation_html, cached
    """
    script_url = parse_input(raw_input)
    script_content = download_script(script_url)
    script_hash = AnalysisCache.hash_script(script_content)

    # Check cache
    cached_entry = AnalysisCache.objects.filter(
        script_url=script_url, script_hash=script_hash
    ).first()

    if cached_entry:
        return {
            "script_url": script_url,
            "script_hash": script_hash,
            "cached": True,
        }

    explanation_md = analyze_script(script_content, script_url)

    # Store in cache (update if URL exists but hash changed)
    AnalysisCache.objects.update_or_create(
        script_url=script_url,
        defaults={
            "input_text": raw_input,
            "script_hash": script_hash,
            "script_content": script_content,
            "explanation_md": explanation_md,
        },
    )

    return {
        "script_url": script_url,
        "script_hash": script_hash,
        "cached": False,
    }
