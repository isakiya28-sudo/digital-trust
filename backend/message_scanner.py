import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List

# Patterns categorized by scam intent
PATTERNS = [
    {
        "id": "credential_otp_harvesting",
        "label": "Credential & OTP Harvesting",
        "severity": "high",
        "weight": 35,
        "description": "Explicit request to disclose one-time passwords (OTP), PINs, CVV, or login credentials.",
        "regexes": [
            r"\b(share|send|enter|verify|provide|give)\b.{0,20}\b(otp|one[- ]time password|verification code|pin|cvv|security code|password)\b",
            r"\b(do not share your|share this)\b.{0,15}\b(otp|code)\b",
            r"\b(otp is|code is)\b.{0,10}\b[0-9]{4,8}\b",
            r"\b(reset|update|confirm)\b.{0,15}\b(password|credentials|login)\b"
        ]
    },
    {
        "id": "financial_urgency_threat",
        "label": "Urgent Threat / Account Suspension",
        "severity": "high",
        "weight": 30,
        "description": "High-pressure urgency threatening immediate account termination, card block, or legal consequence.",
        "regexes": [
            r"\b(account|card|access|service)\b.{0,25}\b(suspended|terminated|blocked|disabled|frozen|locked|restricted)\b",
            r"\bwithin\b.{0,15}\b(24|12|48|1|2|6)\s*(hours|hrs|minutes|mins)\b",
            r"\b(immediate|urgent|action required|final notice|critical alert)\b",
            r"\b(arrest warrant|legal action|law enforcement|court notice|penalty will apply)\b"
        ]
    },
    {
        "id": "lottery_prize_crypto",
        "label": "Fake Prize / Crypto Extortion / Lottery",
        "severity": "high",
        "weight": 30,
        "description": "Unsolicited claims of lottery winnings, unearned prizes, or unrealistic investment windfalls.",
        "regexes": [
            r"\b(you have won|congratulations you won|lottery winner|cash prize|selected for a prize)\b",
            r"\b(\$|€|£|₹)\s*[0-9,]{4,}\b.{0,30}\b(unclaimed|deposited|won|credited|jackpot)\b",
            r"\b(guaranteed profit|100% return|double your crypto|free bitcoin|binance airdrop)\b",
            r"\b(inheritance|beneficiary|foreign diplomat|funds transfer)\b"
        ]
    },
    {
        "id": "brand_service_impersonation",
        "label": "Brand & Institution Impersonation",
        "severity": "medium",
        "weight": 20,
        "description": "Impersonates trusted brands (banks, postal services, e-commerce, government).",
        "regexes": [
            r"\b(wells fargo|chase bank|bank of america|citibank|paypal|barclays|hdfc|sbi|icici)\b",
            r"\b(usps|fedex|dhl|ups|postal service|courier)\b.{0,30}\b(failed delivery|package held|address incomplete|redelivery fee)\b",
            r"\b(amazon|netflix|apple id|microsoft|geek squad)\b.{0,30}\b(billing issue|membership renewal|order placed)\b",
            r"\b(irs|hmrc|tax refund|internal revenue)\b"
        ]
    },
    {
        "id": "unusual_payment_methods",
        "label": "Suspicious Payment Demand",
        "severity": "high",
        "weight": 25,
        "description": "Demands untraceable or non-standard payment methods such as gift cards or cryptocurrency.",
        "regexes": [
            r"\b(apple gift card|google play card|steam card|amazon gift card)\b",
            r"\b(pay via bitcoin|send crypto|usdt wallet|btc address)\b",
            r"\b(western union|moneygram|wire transfer immediately)\b"
        ]
    },
    {
        "id": "suspicious_action_link",
        "label": "Coercive Action Trap / Malicious Link",
        "severity": "medium",
        "weight": 15,
        "description": "Coerces the recipient to click an external link or download an attachment to resolve an artificial crisis.",
        "regexes": [
            r"\b(click here|click link|tap here|visit link|open attachment)\b",
            r"https?://[^\s]+",
            r"\b(bit\.ly|tinyurl\.com|t\.co|is\.gd|cutt\.ly)/[^\s]+"
        ]
    }
]

def sanitize_summary(text: str, max_chars: int = 120) -> str:
    """Mask OTPs/passwords and truncate for safe audit logging."""
    redacted = re.sub(r"\b\d{4,8}\b", "[REDACTED-NUM]", text)
    redacted = re.sub(r"(?i)password[:\s]+[^\s]+", "password: [REDACTED]", redacted)
    clean = " ".join(redacted.split())
    if len(clean) > max_chars:
        return clean[:max_chars] + "..."
    return clean

def scan_message(text: str) -> Dict[str, Any]:
    text_lower = text.lower()
    indicators = []
    highlighted_phrases = set()
    raw_score = 0
    high_severity_count = 0

    for item in PATTERNS:
        matched = []
        for reg in item["regexes"]:
            for match in re.finditer(reg, text, flags=re.IGNORECASE):
                phrase = match.group(0).strip()
                if phrase and phrase not in matched and len(phrase) < 80:
                    matched.append(phrase)
                    highlighted_phrases.add(phrase)

        if matched:
            indicators.append({
                "id": item["id"],
                "label": item["label"],
                "severity": item["severity"],
                "description": item["description"],
                "matched_phrases": matched[:5]
            })
            raw_score += item["weight"]
            if item["severity"] == "high":
                high_severity_count += 1

    # Multi-factor multiplier: if multiple independent high-severity attack vectors align
    if high_severity_count >= 2:
        raw_score += 20
    elif high_severity_count == 1 and len(indicators) >= 2:
        raw_score += 10

    # Baseline adjustment: short vague messages or text with suspicious short links
    if len(text.strip()) > 0 and len(indicators) == 0:
        # Check if there are foreign scripts or random character strings
        if re.search(r"https?://", text):
            raw_score = 15
        else:
            raw_score = 5

    final_score = min(100, max(0, raw_score))

    if final_score >= 65:
        risk_category = "High Risk"
    elif final_score >= 30:
        risk_category = "Medium Risk"
    else:
        risk_category = "Low Risk"

    # Generate contextual explanation
    if final_score >= 65:
        explanation = (
            f"High-risk detection: Identified {len(indicators)} significant threat indicator(s), including "
            f"{', '.join([i['label'] for i in indicators[:2]])}. "
            f"The message demonstrates characteristic patterns of an intentional social engineering or financial harvesting attempt."
        )
    elif final_score >= 30:
        explanation = (
            f"Medium-risk detection: Message contains elements ({', '.join([i['label'] for i in indicators])}) "
            f"commonly observed in unsolicited promotions, unexpected alerts, or ambiguous requests. Exercise elevated caution."
        )
    else:
        explanation = (
            "Low-risk estimation: No typical scam heuristics or credential-harvesting patterns were triggered. "
            "Note: Automated analysis cannot guarantee sender authenticity. Never disclose security codes or passwords to any party."
        )

    # Actionable safety recommendations
    recommendations = []
    if final_score >= 65:
        recommendations.append("Do NOT click any links, open attachments, or dial phone numbers listed inside the message.")
        recommendations.append("Never share one-time passcodes (OTP), CVV numbers, PINs, or account credentials under any circumstances.")
        recommendations.append("Contact the claimed organization directly through their verified public website or customer service line.")
        recommendations.append("Mark this sender as Spam / Phishing in your email or messaging client and block the address.")
    elif final_score >= 30:
        recommendations.append("Do not respond impulsively to the stated deadline or urgency.")
        recommendations.append("Inspect the exact sender email address or phone number carefully for subtle misspellings.")
        recommendations.append("Verify delivery status or account notices by opening the service's official app separately.")
    else:
        recommendations.append("Verify the sender's identity through a trusted alternative channel if the message was unexpected.")
        recommendations.append("Remember that legitimate institutions will never ask for your confidential password or OTP.")

    target_summary = sanitize_summary(text)
    scan_id = f"msg-{uuid.uuid4().hex[:10]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    return {
        "scan_id": scan_id,
        "scan_type": "message",
        "target_summary": target_summary,
        "risk_score": final_score,
        "risk_category": risk_category,
        "indicators": indicators,
        "highlighted_phrases": list(highlighted_phrases),
        "explanation": explanation,
        "recommendations": recommendations,
        "is_ai_fallback": True,
        "scoring_method": "Documented Weighted Heuristic Pattern Engine (v2.1) with Coercion Analysis",
        "timestamp": now_iso,
        "details": {
            "char_count": len(text),
            "word_count": len(text.split()),
            "threat_factors_detected": len(indicators),
            "high_severity_count": high_severity_count
        }
    }
