import sqlite3
import json
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

DB_FILE = os.path.join(os.path.dirname(__file__), "digital_trust.db")

def get_db_connection():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                scan_type TEXT NOT NULL,
                target_summary TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                risk_category TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                indicators_json TEXT NOT NULL,
                explanation TEXT NOT NULL,
                recommendations_json TEXT NOT NULL,
                details_json TEXT NOT NULL,
                is_demo INTEGER DEFAULT 0
            )
        """)
        
        # Check if table is empty. If so, seed initial sample data labeled as demo
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        if count == 0:
            seed_initial_demo_scans(conn)
    conn.close()

def seed_initial_demo_scans(conn):
    sample_scans = [
        (
            "demo-msg-01",
            "message",
            "URGENT: Your Bank of America debit card has been suspended. Click link immediately...",
            92,
            "High Risk",
            datetime.now(timezone.utc).isoformat(),
            json.dumps([
                {"id": "bank_impersonation", "label": "Bank Impersonation", "severity": "high", "description": "Spoofs a recognized banking institution", "matched_phrases": ["Bank of America"]},
                {"id": "urgency_panic", "label": "Urgency / Threat", "severity": "high", "description": "Creates false urgency to bypass rational judgment", "matched_phrases": ["URGENT", "suspended"]},
                {"id": "credential_trap", "label": "Credential Harvesting", "severity": "high", "description": "Pressures user to verify credentials through external link", "matched_phrases": ["Click link immediately"]}
            ]),
            "Automated Heuristic Engine detected 3 high-severity indicators: Financial impersonation, artificial urgency, and credential fishing.",
            json.dumps(["Do not click on links in SMS or email.", "Verify directly by typing official bank URL into your browser.", "Report message to your bank's fraud department."]),
            json.dumps({"source": "Demo Baseline Sample"}),
            1
        ),
        (
            "demo-url-02",
            "url",
            "https://paypa1-account-security-update.secure-login.xyz/auth",
            96,
            "High Risk",
            datetime.now(timezone.utc).isoformat(),
            json.dumps([
                {"id": "typosquatting", "label": "Typosquatting Spoof", "severity": "high", "description": "Replaces 'l' with numeral '1' to deceive users", "matched_phrases": ["paypa1"]},
                {"id": "suspicious_tld", "label": "High-Risk TLD", "severity": "medium", "description": "Uses low-reputation top level domain .xyz", "matched_phrases": [".xyz"]},
                {"id": "excessive_subdomains", "label": "Nested Subdomains", "severity": "medium", "description": "Multiple subdomains designed to hide true root domain", "matched_phrases": ["paypa1-account-security-update", "secure-login"]}
            ]),
            "High probability credential phishing destination mimicking PayPal. Never authenticate on this host.",
            json.dumps(["Never enter passwords or OTPs on this domain.", "Official PayPal domain is strictly paypal.com.", "Close tab immediately."]),
            json.dumps({"source": "Demo Baseline Sample"}),
            1
        ),
        (
            "demo-msg-03",
            "message",
            "Team sync tomorrow at 10:00 AM in Conference Room B. Please review the quarterly deck.",
            8,
            "Low Risk",
            datetime.now(timezone.utc).isoformat(),
            json.dumps([]),
            "No common phishing, credential harvesting, or extortion patterns were detected in this message.",
            json.dumps(["Standard workplace communication.", "Continue practicing general digital hygiene."]),
            json.dumps({"source": "Demo Baseline Sample"}),
            1
        ),
        (
            "demo-url-04",
            "url",
            "https://github.com/features/security",
            5,
            "Low Risk",
            datetime.now(timezone.utc).isoformat(),
            json.dumps([
                {"id": "valid_ssl", "label": "HTTPS Active", "severity": "info", "description": "Standard TLS transport encryption in use", "matched_phrases": ["https"]}
            ]),
            "Standard legitimate enterprise host with valid HTTPS structure and recognized domain authority.",
            json.dumps(["Domain appears standard and legitimate.", "Always check the address bar for the exact domain."]),
            json.dumps({"source": "Demo Baseline Sample"}),
            1
        ),
        (
            "demo-cnt-05",
            "content_text",
            "SHOCKING SECRET: Doctors are FURIOUS that this ancient household spice cures all diseases in 48 hours!!",
            82,
            "High Risk",
            datetime.now(timezone.utc).isoformat(),
            json.dumps([
                {"id": "sensationalism", "label": "Sensationalist Clickbait", "severity": "high", "description": "Uses emotional shock value and hyperbolic claims", "matched_phrases": ["SHOCKING SECRET", "FURIOUS"]},
                {"id": "unsubstantiated_medical", "label": "Unsubstantiated Medical Claim", "severity": "high", "description": "Claims universal cure without scientific trial citation", "matched_phrases": ["cures all diseases in 48 hours"]}
            ]),
            "Text exhibits classic viral misinformation and pseudoscience clickbait characteristics.",
            json.dumps(["Consult verified medical sources (WHO, CDC, Mayo Clinic).", "Cross-check on independent fact-check sites (Reuters Fact Check, Snopes)."]),
            json.dumps({"source": "Demo Baseline Sample"}),
            1
        )
    ]
    cursor = conn.cursor()
    cursor.executemany("""
        INSERT INTO scans (id, scan_type, target_summary, risk_score, risk_category, timestamp, indicators_json, explanation, recommendations_json, details_json, is_demo)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, sample_scans)

def insert_scan(scan_dict: Dict[str, Any]) -> None:
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT INTO scans (id, scan_type, target_summary, risk_score, risk_category, timestamp, indicators_json, explanation, recommendations_json, details_json, is_demo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (
            scan_dict["scan_id"],
            scan_dict["scan_type"],
            scan_dict["target_summary"],
            scan_dict["risk_score"],
            scan_dict["risk_category"],
            scan_dict["timestamp"],
            json.dumps(scan_dict.get("indicators", [])),
            scan_dict["explanation"],
            json.dumps(scan_dict.get("recommendations", [])),
            json.dumps(scan_dict.get("details", {}))
        ))
    conn.close()

def get_recent_scans(limit: int = 15) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, scan_type, target_summary, risk_score, risk_category, timestamp, indicators_json, explanation
        FROM scans
        ORDER BY timestamp DESC
        LIMIT ?
    """, (limit,))
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        try:
            indicators = json.loads(r["indicators_json"])
        except Exception:
            indicators = []
        results.append({
            "id": r["id"],
            "scan_type": r["scan_type"],
            "target_summary": r["target_summary"],
            "risk_score": r["risk_score"],
            "risk_category": r["risk_category"],
            "timestamp": r["timestamp"],
            "indicator_count": len(indicators),
            "explanation": r["explanation"]
        })
    return results

def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM scans")
    total_scans = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'Low Risk'")
    low_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'Medium Risk'")
    medium_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM scans WHERE risk_category = 'High Risk'")
    high_risk = cursor.fetchone()[0]
    
    cursor.execute("SELECT scan_type, COUNT(*) FROM scans GROUP BY scan_type")
    type_counts = {}
    for st, cnt in cursor.fetchall():
        type_counts[st] = cnt
        
    cursor.execute("SELECT COUNT(*) FROM scans WHERE is_demo = 1")
    demo_count = cursor.fetchone()[0]
    is_demo_only = (total_scans > 0 and demo_count == total_scans)
    
    conn.close()
    
    recent = get_recent_scans(8)
    
    return {
        "total_scans": total_scans,
        "low_risk_count": low_risk,
        "medium_risk_count": medium_risk,
        "high_risk_count": high_risk,
        "scan_types": type_counts,
        "recent_scans": recent,
        "is_demo_data": is_demo_only
    }

def clear_all_scans():
    conn = get_db_connection()
    with conn:
        conn.execute("DELETE FROM scans")
    conn.close()
