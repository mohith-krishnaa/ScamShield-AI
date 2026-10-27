"""Transparent text and URL indicators for the ScamShield AI educational prototype.

These rules are explainable heuristics, not proof that a message or URL is malicious.
"""
from __future__ import annotations
import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.IGNORECASE)

PATTERNS = [
    ("Requests an OTP, password, PIN, or verification code", r"\b(otp|one[- ]time password|password|passcode|pin|verification code|security code|recovery code)\b"),
    ("Uses urgency or threat language", r"\b(urgent|immediately|within \d+ hours?|account blocked|suspended|expire[sd]? today|final warning|act now|avoid suspension|last chance)\b"),
    ("Claims a prize, reward, refund, or unexpected money", r"\b(won|winner|prize|reward|cashback|refund|lottery|claim your|free gift|selected for|cash prize)\b"),
    ("Asks the recipient to click or verify through a link", r"\b(click|tap|verify|confirm|update your|login|log in|sign in|open this link|visit the link)\b"),
    ("Uses a known URL-shortener pattern", r"(?:https?://)?(?:bit\.ly|tinyurl\.com|t\.co|cutt\.ly|rb\.gy|is\.gd|ow\.ly|shorturl\.at)/"),
    ("Uses payment or transfer pressure", r"\b(pay now|transfer now|send money|upi|gift card|processing fee|bank details|payment required|pay a fee)\b"),
    ("Uses a generic greeting", r"\b(dear customer|dear user|valued customer|congratulations customer|dear account holder)\b"),
    ("Promises unusually easy or guaranteed income", r"\b(guaranteed income|earn \d+%|risk[- ]free profit|double your money|work from home.*fee)\b"),
    ("Requests secrecy or discourages independent verification", r"\b(do not tell anyone|keep this confidential|don't contact your bank|do not call customer care)\b"),
]
SUSPICIOUS_TLDS = {"zip", "mov", "click", "top", "work", "country", "gq", "tk", "rest", "fit"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "ow.ly", "shorturl.at", "rebrand.ly"}

def extract_urls(text: str) -> list[str]:
    """Extract explicit http(s) and www URLs without fetching them."""
    urls = []
    for match in URL_RE.findall(text or ""):
        candidate = match.rstrip(".,!?;:)]}")
        if candidate and candidate not in urls:
            urls.append(candidate)
    return urls

def url_findings(url: str) -> list[str]:
    """Return syntactic URL warnings; this function never performs network requests."""
    candidate = (url or "").strip()
    if not candidate:
        return ["URL is empty"]
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    parsed = urlparse(candidate)
    host = (parsed.hostname or "").lower().rstrip(".")
    findings: list[str] = []
    if parsed.scheme.lower() not in {"http", "https"}:
        findings.append("URL scheme is missing or unusual")
    elif parsed.scheme.lower() != "https":
        findings.append("URL does not use HTTPS")
    if not host:
        findings.append("Could not parse a hostname from this URL")
        return findings
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        findings.append("URL contains user-info or an @ symbol in its authority section")
    try:
        ipaddress.ip_address(host)
        findings.append("URL uses an IP address instead of a domain name")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        findings.append("Hostname contains a punycode label; inspect the displayed domain carefully")
    if host.count("-") >= 3:
        findings.append("Hostname contains many hyphens")
    if len(host) > 45:
        findings.append("Hostname is unusually long")
    if host.count(".") >= 4:
        findings.append("Hostname has many subdomain levels")
    labels = host.split(".")
    if len(labels) >= 2 and labels[-1] in SUSPICIOUS_TLDS:
        findings.append("Top-level domain is on this prototype's caution list; TLD alone does not imply fraud")
    if host in SHORTENERS:
        findings.append("URL uses a link-shortening service, which hides the final destination")
    if len(parsed.query) > 160:
        findings.append("URL has a long query string that may contain tracking or encoded parameters")
    if re.search(r"\.(exe|scr|bat|cmd|msi|apk|iso)(?:$|/)", parsed.path, re.IGNORECASE):
        findings.append("URL path appears to reference an executable or installable file")
    if any(ord(ch) < 32 for ch in candidate):
        findings.append("URL contains control characters")
    return list(dict.fromkeys(findings))

def analyze_text_indicators(text: str) -> list[str]:
    """Return text-only pattern warnings."""
    lowered = (text or "").lower()
    return [label for label, pattern in PATTERNS if re.search(pattern, lowered, re.IGNORECASE)]

def analyze_indicators(text: str) -> tuple[list[str], list[str]]:
    findings = analyze_text_indicators(text)
    urls = extract_urls(text or "")
    for url in urls:
        findings.extend(url_findings(url))
    return list(dict.fromkeys(findings)), urls

def risk_score(model_scam_score_percent: float, warning_count: int, url_warning_count: int = 0) -> int:
    """Create a transparent demo index, not a calibrated probability."""
    model_component = max(0, min(45, round(float(model_scam_score_percent) * 0.45)))
    text_component = min(35, max(0, warning_count) * 7)
    url_component = min(20, max(0, url_warning_count) * 5)
    return min(100, model_component + text_component + url_component)

def risk_level(score: int) -> tuple[str, str]:
    if score >= 65:
        return "High risk signals", "🔴"
    if score >= 35:
        return "Caution advised", "🟠"
    return "Fewer detected risk signals", "🟢"
