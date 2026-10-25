import re
import io
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List
from PIL import Image, ExifTags

SENSATIONAL_PATTERNS = [
    {
        "id": "clickbait_hyperbole",
        "label": "Sensationalist Clickbait / Hyperbolic Language",
        "severity": "medium",
        "weight": 25,
        "description": "Uses provocative, hyperbolic terms aimed at triggering heightened emotional engagement.",
        "regexes": [
            r"\b(shocking secret|you won\'?t believe|doctors are furious|mind[- ]blowing|terrifying truth)\b",
            r"\b(miracle cure|cures all diseases|instant weight loss|secret ingredient|banned by big pharma)\b",
            r"\b(100% proven|zero risk|guaranteed result in 24 hours)\b"
        ]
    },
    {
        "id": "viral_coercion",
        "label": "Viral Forwarding Coercion",
        "severity": "medium",
        "weight": 20,
        "description": "Coerces rapid sharing prior to verification to maximize viral spread.",
        "regexes": [
            r"\b(share before (this is )?deleted|forward to all your contacts|they are hiding this|don\'?t let them delete)\b",
            r"\b(banned video|censored by media|watch before it\'?s taken down)\b"
        ]
    },
    {
        "id": "conspiracy_framing",
        "label": "Conspiracy / Institutional Cover-up Framing",
        "severity": "high",
        "weight": 30,
        "description": "Alleges widespread secret collusions or suppressed scientific truths without verifiable evidence.",
        "regexes": [
            r"\b(what mainstream media won\'?t tell you|globalist agenda|suppressed truth|secret conspiracy)\b",
            r"\b(microchips in|chemtrails|deep state plot|false flag operation)\b"
        ]
    },
    {
        "id": "unattributed_authority",
        "label": "Vague Authority Attribution",
        "severity": "low",
        "weight": 15,
        "description": "Quotes unnamed 'top experts', 'leading doctors', or 'insiders' lacking traceable citations.",
        "regexes": [
            r"\b(top scientists say|leading doctors agree|insiders reveal|sources confirm without proof)\b",
            r"\b(everyone knows that|studies show that)\b"
        ]
    }
]

def scan_text_content(text: str) -> Dict[str, Any]:
    indicators = []
    highlighted_phrases = set()
    raw_score = 0

    for item in SENSATIONAL_PATTERNS:
        matched = []
        for reg in item["regexes"]:
            for match in re.finditer(reg, text, flags=re.IGNORECASE):
                phrase = match.group(0).strip()
                if phrase and phrase not in matched:
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

    # Check excessive capitalization / exclamation marks
    exclamation_count = text.count("!")
    caps_count = sum(1 for c in text if c.isupper())
    total_letters = sum(1 for c in text if c.isalpha())
    caps_ratio = caps_count / max(1, total_letters)

    if caps_ratio > 0.4 and len(text) > 40:
        indicators.append({
            "id": "excessive_capitalization",
            "label": "Excessive Capitalization (Aggressive Tone)",
            "severity": "low",
            "description": f"{int(caps_ratio*100)}% uppercase characters detected, indicating high-pressure emotional tone.",
            "matched_phrases": ["Excessive CAPS"]
        })
        raw_score += 15

    if exclamation_count >= 4:
        indicators.append({
            "id": "excessive_punctuation",
            "label": "Repeated Exclamatory Punctuation",
            "severity": "low",
            "description": f"Contains {exclamation_count} exclamation points commonly used in rage-bait and sensationalism.",
            "matched_phrases": ["!!!"]
        })
        raw_score += 10

    # Multi-factor correlation boost: multiple manipulative vectors
    if len(indicators) >= 2:
        raw_score += 15

    final_score = min(100, max(0, raw_score))
    if final_score >= 65:
        risk_category = "High Risk"
    elif final_score >= 30:
        risk_category = "Medium Risk"
    else:
        risk_category = "Low Risk"

    # Contextual explanation with epistemological distinction
    if final_score >= 65:
        explanation = (
            "Elevated sensationalism and unverified assertion patterns detected. "
            "Important distinction: A high sensationalism score indicates manipulative framing and lacking evidentiary rigor, "
            "which strongly warrants independent fact-checking, but does not technically prove falsity without primary source cross-referencing."
        )
    elif final_score >= 30:
        explanation = (
            "Moderate presence of emotional rhetoric or unverified generalizations. "
            "Claims presented here should be vetted against established journalistic and scientific authorities before being accepted as factual."
        )
    else:
        explanation = (
            "Low sensationalism detected. Content exhibits conventional declarative phrasing. "
            "Always verify specific empirical claims with authoritative reference documentation."
        )

    recommendations = [
        "Cross-check specific claims on verified fact-checking platforms such as AP News Fact Check, Reuters Fact Check, or Snopes.",
        "Locate the primary source: Look for direct peer-reviewed journal links or official government agency announcements.",
        "Be wary of content demanding immediate sharing or claiming that information is being censored."
    ]

    clean_summary = " ".join(text.split())
    if len(clean_summary) > 100:
        clean_summary = clean_summary[:100] + "..."

    return {
        "scan_id": f"cnt-txt-{uuid.uuid4().hex[:10]}",
        "scan_type": "content_text",
        "target_summary": clean_summary,
        "risk_score": final_score,
        "risk_category": risk_category,
        "indicators": indicators,
        "highlighted_phrases": list(highlighted_phrases),
        "explanation": explanation,
        "recommendations": recommendations,
        "is_ai_fallback": True,
        "scoring_method": "Heuristic NLP Sensationalism & Disinformation Rhetoric Analyzer (v2.1)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "exclamation_points": exclamation_count,
            "capitalization_ratio": round(caps_ratio, 2),
            "verification_sources": ["Reuters Fact Check", "AP Fact Check", "Snopes.com", "PolitiFact"]
        }
    }

def scan_image_content(file_bytes: bytes, filename: str) -> Dict[str, Any]:
    """Inspects image metadata, EXIF, and structure safely."""
    max_size = 10 * 1024 * 1024  # 10 MB limit
    if len(file_bytes) > max_size:
        return {
            "scan_id": f"cnt-img-{uuid.uuid4().hex[:10]}",
            "scan_type": "content_image",
            "target_summary": f"Image: {filename}",
            "risk_score": 50,
            "risk_category": "Medium Risk",
            "indicators": [{
                "id": "oversized_image",
                "label": "File Size Exceeds Limit",
                "severity": "medium",
                "description": "File exceeds the maximum safe upload threshold of 10 MB.",
                "matched_phrases": [f"{len(file_bytes)//1024} KB"]
            }],
            "highlighted_phrases": [],
            "explanation": "File size exceeds the 10 MB safety threshold.",
            "recommendations": ["Compress or resize the image before resubmitting."],
            "is_ai_fallback": True,
            "scoring_method": "File Container & EXIF Inspector",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {}
        }

    try:
        image = Image.open(io.BytesIO(file_bytes))
        image.verify()  # Verify image integrity
        # Re-open because verify() closes the stream or invalidates state
        image = Image.open(io.BytesIO(file_bytes))
    except Exception as e:
        return {
            "scan_id": f"cnt-img-{uuid.uuid4().hex[:10]}",
            "scan_type": "content_image",
            "target_summary": f"Corrupt File: {filename}",
            "risk_score": 75,
            "risk_category": "High Risk",
            "indicators": [{
                "id": "invalid_image_format",
                "label": "Invalid or Corrupted Image Structure",
                "severity": "high",
                "description": "File headers do not match a valid, safely decodable image structure.",
                "matched_phrases": [filename]
            }],
            "highlighted_phrases": [],
            "explanation": f"Security validation failed: File could not be parsed as a safe image format ({str(e)}).",
            "recommendations": ["Ensure file is a genuine PNG, JPEG, WEBP, or GIF image.", "Do not execute unverified file downloads."],
            "is_ai_fallback": True,
            "scoring_method": "Image Header Validation & Safe Parsing",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "details": {"error": str(e)}
        }

    indicators = []
    highlighted_phrases = []
    raw_score = 15  # Baseline

    # Extract EXIF if available
    exif_data = {}
    try:
        raw_exif = image.getexif()
        if raw_exif:
            for tag_id, value in raw_exif.items():
                tag_name = ExifTags.TAGS.get(tag_id, str(tag_id))
                exif_data[tag_name] = str(value)
    except Exception:
        pass

    # Check for AI generation software tags
    software = exif_data.get("Software", "").lower()
    artist = exif_data.get("Artist", "").lower()
    description = exif_data.get("ImageDescription", "").lower()

    ai_keywords = ["stable diffusion", "midjourney", "dall-e", "comfyui", "photoshop", "novelai", "flux", "bing image creator"]
    detected_ai_software = [k for k in ai_keywords if k in software or k in artist or k in description]

    if detected_ai_software:
        indicators.append({
            "id": "ai_synthesis_metadata",
            "label": "Synthetic / Generative Tool Signature in Metadata",
            "severity": "high",
            "description": f"Image metadata specifically documents creation or processing with: {', '.join(detected_ai_software)}.",
            "matched_phrases": detected_ai_software
        })
        highlighted_phrases.extend(detected_ai_software)
        raw_score += 55

    # Check for complete metadata stripping
    if not exif_data and image.format in ["JPEG", "TIFF"]:
        indicators.append({
            "id": "metadata_stripped",
            "label": "EXIF Metadata Stripped / Absent",
            "severity": "low",
            "description": "Standard camera acquisition metadata is absent. This is standard for social media uploads but prevents hardware provenance verification.",
            "matched_phrases": ["No EXIF"]
        })
        raw_score += 10
    elif exif_data:
        indicators.append({
            "id": "metadata_present",
            "label": "Hardware / Sensor Provenance Tags Found",
            "severity": "info",
            "description": f"Found valid EXIF tags ({len(exif_data)} fields), including Make/Model: {exif_data.get('Make', 'N/A')} {exif_data.get('Model', '')}.",
            "matched_phrases": [exif_data.get('Make', 'EXIF')]
        })

    final_score = min(100, max(0, raw_score))
    if final_score >= 65:
        risk_category = "High Risk"
    elif final_score >= 30:
        risk_category = "Medium Risk"
    else:
        risk_category = "Low Risk"

    explanation = (
        f"Forensic structural inspection completed for {filename} ({image.format}, {image.width}x{image.height}px). "
        "Honest System Notice: Heuristic metadata and container inspection was performed. "
        "Advanced deepfake neural classification (pixel artifact latent space analysis) is NOT configured on this server instance. "
        "No claim of absolute image authenticity or deepfake certainty can be made without dedicated neural forensic models."
    )

    recommendations = [
        "Perform a reverse image search using Google Lens, TinEye, or Yandex to find earlier authentic occurrences.",
        "Examine background details, reflections, ear symmetry, finger anatomy, and lighting consistency for generative anomalies.",
        "Notice: Do not rely solely on visual inspection to determine if an image is authentic or generated."
    ]

    return {
        "scan_id": f"cnt-img-{uuid.uuid4().hex[:10]}",
        "scan_type": "content_image",
        "target_summary": f"{filename} ({image.format}, {image.width}x{image.height})",
        "risk_score": final_score,
        "risk_category": risk_category,
        "indicators": indicators,
        "highlighted_phrases": highlighted_phrases,
        "explanation": explanation,
        "recommendations": recommendations,
        "is_ai_fallback": True,
        "scoring_method": "Forensic EXIF Provenance & Structural File Analyzer (v2.1)",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": {
            "format": image.format,
            "dimensions": f"{image.width}x{image.height}",
            "mode": image.mode,
            "file_size_kb": len(file_bytes) // 1024,
            "exif_summary": {k: exif_data[k] for k in list(exif_data.keys())[:6]},
            "neural_deepfake_engine": "Unconfigured (Honest Fallback)"
        }
    }
