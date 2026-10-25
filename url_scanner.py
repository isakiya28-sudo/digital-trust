import re
import ipaddress
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse, unquote
from typing import Dict, Any, List

# Suspicious Top-Level Domains (TLDs) frequently abused in fast-flux phishing campaigns
HIGH_RISK_TLDS = {
    ".xyz", ".top", ".club", ".work", ".click", ".surf", ".gq", ".cf", ".tk", ".ml", ".ga",
    ".fit", ".zip", ".mov", ".country", ".kim", ".rest", ".stream", ".live", ".cc"
}

# Targeted high-value brands often spoofed
BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix", "chase",
    "wellsfargo", "bankofamerica", "citibank", "binance", "coinbase", "metamask",
    "instagram", "facebook", "whatsapp", "telegram", "dhl", "fedex", "usps"
]

def check_ssrf_risk(hostname: str) -> bool:
    """Check if hostname points to internal/private/loopback/cloud metadata IP."""
    if not hostname:
        return True
    host_clean = hostname.strip().lower()
    if host_clean in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "metadata.google.internal"}:
        return True
    try:
        ip = ipaddress.ip_address(host_clean)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return True
        # Cloud metadata IP (AWS, Azure, GCP, DigitalOcean)
        if str(ip) == "169.254.169.254":
            return True
    except ValueError:
        pass
    return False

def scan_url(raw_url: str) -> Dict[str, Any]:
    url = raw_url.strip()
    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "https://" + url

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
    except Exception as e:
        return {
            "scan_id": f"url-{uuid.uuid4().hex[:10]}",
            "scan_type": "url",
            "target_summary": raw_url[:80],
            "risk_score": 85,
            "risk_category": "High Risk",
            "indicators": [{
                "id": "malformed_url",
                "label": "Malformed / Invalid URL Structure",
                "severity": "high",
                "description": "The submitted URL could not be safely parsed by RFC standards.",
                "matched_phrases": [raw_url[:40]]
            }],
            "highlighted_phrases": [raw_url[:40]],
            "explanation": "Malformed URL syntax detected. Attackers frequently utilize malformed URLs to evade automated filters.",
            "recommendations": ["Do not click or load this link.", "Check the URL syntax manually."],
            "is_ai_fallback": True,
            "scoring_method": "Heuristic URL Parser & RFC Validator",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {"error": str(e)}
        }

    indicators: List[Dict[str, Any]] = []
    highlighted_phrases: List[str] = []
    raw_score = 0

    # 1. SSRF and Private IP detection
    if check_ssrf_risk(hostname):
        indicators.append({
            "id": "ssrf_private_host",
            "label": "Private / Internal Network Host (SSRF Hazard)",
            "severity": "high",
            "description": "Host targets a private, loopback, or cloud-internal metadata network (RFC 1918).",
            "matched_phrases": [hostname]
        })
        highlighted_phrases.append(hostname)
        raw_score += 60

    # 2. IP Address host instead of domain
    is_ip_host = False
    try:
        ipaddress.ip_address(hostname)
        is_ip_host = True
        indicators.append({
            "id": "ip_address_host",
            "label": "Direct IP-Address Hostname",
            "severity": "high",
            "description": "URL bypasses standard domain name hierarchy using a direct IP address, typical in drive-by malware drops.",
            "matched_phrases": [hostname]
        })
        highlighted_phrases.append(hostname)
        raw_score += 40
    except ValueError:
        pass

    # 3. Protocol evaluation (HTTPS vs HTTP)
    if parsed.scheme.lower() == "http":
        indicators.append({
            "id": "unencrypted_http",
            "label": "Unencrypted HTTP Protocol",
            "severity": "medium",
            "description": "Transmission is completely unencrypted. Intermediaries can read and tamper with traffic.",
            "matched_phrases": ["http://"]
        })
        highlighted_phrases.append("http://")
        raw_score += 25
    else:
        indicators.append({
            "id": "https_transport",
            "label": "HTTPS Transport Encryption",
            "severity": "info",
            "description": "Connection uses TLS encryption. (Note: Scammers also acquire free SSL certificates; HTTPS does NOT guarantee trustworthiness).",
            "matched_phrases": ["https://"]
        })

    # 4. High-risk TLD check
    tld_matched = None
    for tld in HIGH_RISK_TLDS:
        if hostname.endswith(tld):
            tld_matched = tld
            break
    if tld_matched:
        indicators.append({
            "id": "suspicious_tld",
            "label": f"High-Abuse Top-Level Domain ({tld_matched})",
            "severity": "medium",
            "description": f"Domain utilizes '{tld_matched}', a TLD with statistically elevated phishing and spam incidence.",
            "matched_phrases": [tld_matched]
        })
        highlighted_phrases.append(tld_matched)
        raw_score += 25

    # 5. Typosquatting and Brand Spoofing
    host_parts = hostname.split(".")
    subdomain_count = len(host_parts) - 2 if len(host_parts) >= 2 else 0

    for brand in BRAND_KEYWORDS:
        # Check if brand appears in subdomain or domain with typos
        typo_variants = [
            brand.replace("l", "1"),
            brand.replace("o", "0"),
            brand.replace("i", "1"),
            brand.replace("e", "3"),
            f"{brand}-security",
            f"{brand}-login",
            f"{brand}-verify",
            f"{brand}-support",
            f"{brand}update"
        ]
        for variant in typo_variants:
            if variant in hostname and not hostname.endswith(f".{brand}.com") and hostname != f"{brand}.com":
                indicators.append({
                    "id": "brand_typosquatting",
                    "label": f"Brand Impersonation / Typosquatting ({brand.title()})",
                    "severity": "high",
                    "description": f"Domain contains deceptive spoof '{variant}' designed to mimic legitimate brand '{brand.title()}'.",
                    "matched_phrases": [variant]
                })
                highlighted_phrases.append(variant)
                raw_score += 45
                break

    # 6. Excessive subdomains
    if subdomain_count >= 3:
        indicators.append({
            "id": "excessive_subdomains",
            "label": f"Deeply Nested Subdomains ({subdomain_count} levels)",
            "severity": "medium",
            "description": "Deep subdomain nesting is frequently used to display a trusted brand name while concealing the true apex domain.",
            "matched_phrases": [hostname]
        })
        highlighted_phrases.append(hostname)
        raw_score += 20

    # 7. Suspicious Path & Query Keywords
    sensitive_path_keywords = ["login", "signin", "verify", "account", "banking", "wallet", "update", "auth", "confirm", "security"]
    found_path_keywords = [kw for kw in sensitive_path_keywords if kw in path.lower() or kw in query.lower()]
    if found_path_keywords and (tld_matched or is_ip_host or subdomain_count >= 2):
        indicators.append({
            "id": "credential_path_keywords",
            "label": "Credential Lure in Path / Query",
            "severity": "high",
            "description": f"URL path targets authentication vectors: {', '.join(found_path_keywords)} on an unverified domain.",
            "matched_phrases": found_path_keywords
        })
        highlighted_phrases.extend(found_path_keywords)
        raw_score += 25

    # 8. Excessive URL length
    if len(url) > 110:
        indicators.append({
            "id": "excessive_length",
            "label": f"Unusually Long URL ({len(url)} chars)",
            "severity": "low",
            "description": "Extremely long URLs are commonly used to push the actual domain out of view in mobile address bars.",
            "matched_phrases": [url[:60] + "..."]
        })
        raw_score += 15

    # 9. Dangerous characters or @ credential masking
    if "@" in url:
        indicators.append({
            "id": "at_symbol_masking",
            "label": "User-Info '@' Address Redirection Trick",
            "severity": "high",
            "description": "The '@' symbol causes browsers to ignore all preceding characters and route only to what follows it.",
            "matched_phrases": ["@"]
        })
        highlighted_phrases.append("@")
        raw_score += 50

    # Check for homoglyphs / Punycode (IDN spoofing)
    if hostname.startswith("xn--"):
        indicators.append({
            "id": "punycode_homoglyph",
            "label": "Internationalized Domain Name (Punycode / Homoglyph)",
            "severity": "high",
            "description": "Domain uses Punycode encoding, frequently employed to spoof Latin characters with visually identical Cyrillic/Greek characters.",
            "matched_phrases": [hostname]
        })
        highlighted_phrases.append(hostname)
        raw_score += 35

    final_score = min(100, max(0, raw_score))

    if final_score >= 65:
        risk_category = "High Risk"
    elif final_score >= 30:
        risk_category = "Medium Risk"
    else:
        risk_category = "Low Risk"

    # Explanation
    if final_score >= 65:
        explanation = (
            f"High-Risk URL detected with an estimated risk score of {final_score}/100. "
            f"Key red flags include {', '.join([i['label'] for i in indicators if i['severity'] == 'high'][:2])}. "
            "Visiting this link carries a severe probability of credential theft, session hijacking, or malicious payload delivery."
        )
    elif final_score >= 30:
        explanation = (
            f"Medium-Risk URL with an estimated risk score of {final_score}/100. "
            f"Flagged attributes include {', '.join([i['label'] for i in indicators[:2]])}. "
            "While not definitively confirmed malicious, the domain architecture deviates from standard trusted web hygiene."
        )
    else:
        explanation = (
            f"Low-Risk evaluation ({final_score}/100). The URL conforms to standard domain conventions. "
            "Reminder: Heuristic scanning checks structural and reputational signals. Always inspect the exact domain before entering credentials."
        )

    recommendations = []
    if final_score >= 65:
        recommendations.append("DO NOT visit this URL in your web browser or enter any usernames/passwords.")
        recommendations.append("If this link was received via email or SMS, report it immediately to your organization's security team.")
        recommendations.append("If you already visited and submitted credentials, change your password immediately on the official site.")
    elif final_score >= 30:
        recommendations.append("Double-check the apex domain spelling in the address bar before interacting with forms.")
        recommendations.append("Avoid providing financial or personal information unless domain ownership is verified.")
    else:
        recommendations.append("Always verify that the website domain matches the company you intend to do business with.")
        recommendations.append("Ensure your browser and security patches are up to date.")

    scan_id = f"url-{uuid.uuid4().hex[:10]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "scan_id": scan_id,
        "scan_type": "url",
        "target_summary": raw_url[:100],
        "risk_score": final_score,
        "risk_category": risk_category,
        "indicators": indicators,
        "highlighted_phrases": list(set(highlighted_phrases)),
        "explanation": explanation,
        "recommendations": recommendations,
        "is_ai_fallback": True,
        "scoring_method": "Heuristic Structural DNS & RFC Security Vector Analyzer (v2.1)",
        "timestamp": now_iso,
        "details": {
            "parsed_scheme": parsed.scheme,
            "parsed_hostname": hostname,
            "subdomain_depth": subdomain_count,
            "is_ip_address": is_ip_host,
            "reputation_source": "Local RFC Heuristic Engine (External Live Threat Feed Unconfigured)"
        }
    }
