from modules.database import insert_scan
import html
import json
import os
import re
from datetime import datetime, timezone


def _safe_filename(name):
    return re.sub(r"[^a-zA-Z0-9_-]", "_", name)[:40]


def calculate_exposure_summary(username_data=None, domain_data=None):
    """Calculates an educational Digital Footprint Exposure Level based on public findings."""
    score = 0
    notes = []

    if username_data:
        found = [r for r in username_data.get("results", []) if r["status"] == "FOUND"]
        count = len(found)
        score += min(count * 8, 50)
        if count >= 6:
            notes.append(f"High handle reuse detected across {count} public platforms.")
        elif count >= 2:
            notes.append(f"Moderate handle reuse detected across {count} public platforms.")
        elif count == 1:
            notes.append("Single public social profile identified for this handle.")
        else:
            notes.append("No public social accounts matched this handle on checked platforms.")

        meta_hits = 0
        for item in found:
            meta = item.get("metadata", {})
            for field in ("display_name", "location", "company", "website", "bio_snippet"):
                if meta.get(field):
                    meta_hits += 1
        if meta_hits >= 4:
            score += 20
            notes.append("Multiple personal attributes (bio, location, links, or name) are publicly exposed.")
        elif meta_hits > 0:
            score += 10
            notes.append("Basic public profile metadata is visible.")

    if domain_data:
        email_sec = domain_data.get("email_security", {})
        if email_sec.get("has_mx"):
            if not email_sec.get("has_spf"):
                score += 10
                notes.append("Domain accepts email (MX) but lacks an SPF record (spoofing risk).")
            if not email_sec.get("has_dmarc"):
                score += 10
                notes.append("Domain lacks a DMARC policy record.")

        headers = domain_data.get("http_headers", {})
        if isinstance(headers, dict) and "error" not in headers:
            missing_sec = [
                h
                for h in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options")
                if headers.get(h) == "Missing"
            ]
            if missing_sec:
                score += min(len(missing_sec) * 5, 15)
                notes.append(f"Missing HTTP security headers: {', '.join(missing_sec)}.")

    score = min(score, 100)
    if score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MODERATE"
    else:
        level = "LOW"

    return {
        "exposure_score": score,
        "exposure_level": level,
        "observations": notes,
    }


def _build_txt_report(payload):
    lines = []
    lines.append("=" * 70)
    lines.append("AUTOMATED OSINT DIGITAL FOOTPRINT AGGREGATION REPORT")
    lines.append("=" * 70)
    lines.append(f"Generated (UTC) : {payload['generated_utc']}")
    lines.append(f"Target Label    : {payload['target_label']}")
    exp = payload["exposure_summary"]
    lines.append(f"Exposure Level  : {exp['exposure_level']} ({exp['exposure_score']}/100)")
    lines.append("-" * 70)

    lines.append("\n[EXECUTIVE OBSERVATIONS]")
    for obs in exp["observations"]:
        lines.append(f"  - {obs}")

    u_data = payload.get("username_recon")
    if u_data:
        lines.append("\n" + "=" * 70)
        lines.append(f"[SOCIAL MEDIA RECONNAISSANCE] Target: {u_data['target_username']}")
        lines.append(
            f"Checked: {u_data['platforms_checked']} | Found: {u_data['accounts_found']} "
            f"| Errors: {u_data['errors_count']} | Time: {u_data['execution_time_sec']}s"
        )
        lines.append("-" * 70)
        found = [r for r in u_data["results"] if r["status"] == "FOUND"]
        if not found:
            lines.append("  No matching public profiles found.")
        for item in found:
            lines.append(
                f"  [+] {item['platform']} ({item['category']}) -> {item['url']} "
                f"[{item['response_time_ms']} ms]"
            )
            for k, v in item.get("metadata", {}).items():
                lines.append(f"        {k}: {v}")

    d_data = payload.get("domain_recon")
    if d_data:
        lines.append("\n" + "=" * 70)
        lines.append(f"[DOMAIN & INFRASTRUCTURE RECON] Target: {d_data['target_domain']}")
        lines.append(
            f"IP Address: {d_data['ip_address']} | Scan Time: {d_data['execution_time_sec']}s"
        )
        lines.append("-" * 70)
        lines.append("  Email Security:")
        for k, v in d_data["email_security"].items():
            lines.append(f"    {k}: {v}")
        lines.append("  WHOIS Summary:")
        for k, v in d_data["whois"].items():
            lines.append(f"    {k}: {v}")
        lines.append("  DNS Records:")
        for rtype, recs in d_data["dns_records"].items():
            if recs:
                lines.append(f"    {rtype}: {', '.join(recs[:5])}")
        lines.append("  HTTP Security Headers:")
        for k, v in d_data["http_headers"].items():
            lines.append(f"    {k}: {v}")

    lines.append("\n" + "=" * 70)
    lines.append("ETHICAL NOTICE: Strictly passive aggregation of publicly available data.")
    lines.append("=" * 70)
    return "\n".join(lines)


def _build_html_report(payload):
    esc = html.escape
    exp = payload["exposure_summary"]
    badge_color = {
        "HIGH": "#ef4444",
        "MODERATE": "#f59e0b",
        "LOW": "#10b981",
    }.get(exp["exposure_level"], "#3b82f6")

    obs_html = "".join(f"<li>{esc(o)}</li>" for o in exp["observations"])

    social_section = ""
    u_data = payload.get("username_recon")
    if u_data:
        found = [r for r in u_data["results"] if r["status"] == "FOUND"]
        rows = ""
        for item in found:
            meta_str = "<br>".join(
                f"<strong>{esc(str(k))}:</strong> {esc(str(v))}"
                for k, v in item.get("metadata", {}).items()
            ) or "<em>No extra metadata</em>"
            rows += (
                f"<tr>"
                f"<td><strong>{esc(item['platform'])}</strong><br><small>{esc(item['category'])}</small></td>"
                f"<td><a href='{esc(item['url'])}' target='_blank'>{esc(item['url'])}</a></td>"
                f"<td>{item['response_time_ms']} ms</td>"
                f"<td>{meta_str}</td>"
                f"</tr>"
            )
        if not rows:
            rows = "<tr><td colspan='4'>No public profiles discovered on checked platforms.</td></tr>"

        social_section = f"""
        <div class="card">
            <h2>Social Media &amp; Username Reconnaissance: @{esc(u_data['target_username'])}</h2>
            <p class="stats">
                Platforms Checked: <strong>{u_data['platforms_checked']}</strong> |
                Accounts Found: <strong>{u_data['accounts_found']}</strong> |
                Errors: <strong>{u_data['errors_count']}</strong> |
                Scan Time: <strong>{u_data['execution_time_sec']}s</strong>
            </p>
            <table>
                <thead><tr><th>Platform</th><th>Profile URL</th><th>Latency</th><th>Public Metadata</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    domain_section = ""
    d_data = payload.get("domain_recon")
    if d_data:
        whois_rows = "".join(
            f"<tr><td><strong>{esc(str(k))}</strong></td><td>{esc(str(v))}</td></tr>"
            for k, v in d_data["whois"].items()
        )
        dns_rows = "".join(
            f"<tr><td><strong>{esc(rtype)}</strong></td><td>{esc(', '.join(recs[:5]))}</td></tr>"
            for rtype, recs in d_data["dns_records"].items()
            if recs
        ) or "<tr><td colspan='2'>No DNS records retrieved.</td></tr>"
        header_rows = "".join(
            f"<tr><td><strong>{esc(str(k))}</strong></td><td>{esc(str(v))}</td></tr>"
            for k, v in d_data["http_headers"].items()
        )
        es = d_data["email_security"]
        domain_section = f"""
        <div class="card">
            <h2>Domain &amp; Infrastructure Footprint: {esc(d_data['target_domain'])}</h2>
            <p class="stats">
                IP Address: <strong>{esc(str(d_data['ip_address']))}</strong> |
                MX: <strong>{es['has_mx']}</strong> |
                SPF: <strong>{es['has_spf']}</strong> |
                DMARC: <strong>{es['has_dmarc']}</strong> |
                Scan Time: <strong>{d_data['execution_time_sec']}s</strong>
            </p>
            <h3>WHOIS Registration</h3>
            <table><tbody>{whois_rows}</tbody></table>
            <h3>DNS Records</h3>
            <table><tbody>{dns_rows}</tbody></table>
            <h3>HTTP Security Headers</h3>
            <table><tbody>{header_rows}</tbody></table>
        </div>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report - {esc(payload['target_label'])}</title>
<style>
  body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 20px; }}
  .container {{ max-width: 1000px; margin: auto; }}
  .header {{ background: #1e293b; padding: 24px; border-radius: 10px; border-left: 6px solid {badge_color}; margin-bottom: 20px; }}
  .badge {{ display: inline-block; padding: 6px 14px; border-radius: 20px; background: {badge_color}; color: #fff; font-weight: bold; font-size: 0.9em; }}
  .card {{ background: #1e293b; padding: 20px; border-radius: 10px; margin-bottom: 20px; overflow-x: auto; }}
  h1, h2, h3 {{ margin-top: 0; color: #38bdf8; }}
  a {{ color: #7dd3fc; word-break: break-all; }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; margin-bottom: 16px; }}
  th, td {{ border: 1px solid #334155; padding: 10px; text-align: left; vertical-align: top; font-size: 0.92em; }}
  th {{ background: #0f172a; color: #94a3b8; }}
  .stats {{ color: #cbd5e1; font-size: 0.95em; }}
  .footer {{ text-align: center; color: #94a3b8; font-size: 0.85em; margin-top: 20px; }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>OSINT Digital Footprint Aggregation Report</h1>
    <p><strong>Target:</strong> {esc(payload['target_label'])} &nbsp;|&nbsp; <strong>Generated (UTC):</strong> {esc(payload['generated_utc'])}</p>
    <p>Exposure Assessment: <span class="badge">{esc(exp['exposure_level'])} ({exp['exposure_score']}/100)</span></p>
    <ul>{obs_html}</ul>
  </div>
  {social_section}
  {domain_section}
  <div class="footer">Generated by Automated OSINT Reconnaissance Tool | Passive Public Data Only</div>
</div>
</body>
</html>
"""


def save_reports(target_label, username_data=None, domain_data=None, output_dir="reports"):
    """Exports JSON, TXT, and HTML reports and returns their file paths."""
    os.makedirs(output_dir, exist_ok=True)
    now = datetime.now(timezone.utc)
    timestamp = now.strftime("%Y%m%d_%H%M%S")
    base = f"osint_{_safe_filename(target_label)}_{timestamp}"

    payload = {
        "target_label": target_label,
        "generated_utc": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "exposure_summary": calculate_exposure_summary(username_data, domain_data),
        "username_recon": username_data,
        "domain_recon": domain_data,
    }

    json_path = os.path.join(output_dir, f"{base}.json")
    txt_path = os.path.join(output_dir, f"{base}.txt")
    html_path = os.path.join(output_dir, f"{base}.html")

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)

    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(_build_txt_report(payload))

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_build_html_report(payload))

    paths = {"json": json_path, "txt": txt_path, "html": html_path}
    scan_id = insert_scan(payload, paths)
    return {
        "scan_id": scan_id,
        "json": json_path,
        "txt": txt_path,
        "html": html_path,
        "exposure_summary": payload["exposure_summary"],
    }
