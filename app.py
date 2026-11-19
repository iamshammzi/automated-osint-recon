#!/usr/bin/env python3
"""
Flask Local Web User Interface for the Automated OSINT Tool.
Integrates Social Media Recon, Domain Recon, and SQLite Database Storage.
"""

import os
from flask import Flask, redirect, render_template_string, request, send_file, url_for

from modules.database import get_recent_scans, get_scan_by_id, init_db
from modules.domain_recon import normalize_domain, run_domain_recon
from modules.report_gen import save_reports
from modules.username_recon import run_username_recon

app = Flask(__name__)
init_db()

TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Automated OSINT Recon Dashboard</title>
<style>
  * { box-sizing: border-box; }
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #0b1120; color: #e2e8f0; margin: 0; padding: 16px; }
  .container { max-width: 1100px; margin: auto; }
  .topbar { background: linear-gradient(135deg, #1e293b, #0f172a); padding: 20px 24px; border-radius: 12px; border-left: 5px solid #38bdf8; margin-bottom: 20px; }
  .topbar h1 { margin: 0 0 6px 0; font-size: 1.45rem; color: #38bdf8; }
  .topbar p { margin: 0; font-size: 0.9rem; color: #94a3b8; }
  .grid { display: grid; grid-template-columns: 1fr; gap: 20px; }
  .card { background: #1e293b; padding: 20px; border-radius: 12px; border: 1px solid #334155; overflow-x: auto; }
  h2 { margin-top: 0; font-size: 1.15rem; color: #38bdf8; border-bottom: 1px solid #334155; padding-bottom: 8px; }
  h3 { color: #7dd3fc; font-size: 1rem; margin-bottom: 8px; }
  .form-row { display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 12px; }
  .form-group { flex: 1; min-width: 220px; }
  label { display: block; font-size: 0.85rem; color: #cbd5e1; margin-bottom: 6px; font-weight: 600; }
  input[type="text"] { width: 100%; padding: 10px 12px; border-radius: 8px; border: 1px solid #475569; background: #0f172a; color: #f8fafc; font-size: 0.95rem; }
  .btn { background: #0284c7; color: #fff; border: none; padding: 11px 20px; border-radius: 8px; font-weight: bold; cursor: pointer; font-size: 0.95rem; text-decoration: none; display: inline-block; }
  .btn:hover { background: #0369a1; }
  .btn-sm { padding: 6px 12px; font-size: 0.82rem; border-radius: 6px; }
  .btn-outline { background: transparent; border: 1px solid #38bdf8; color: #38bdf8; }
  .badge { display: inline-block; padding: 5px 12px; border-radius: 20px; font-weight: bold; font-size: 0.82rem; color: #fff; }
  .HIGH { background: #ef4444; }
  .MODERATE { background: #f59e0b; }
  .LOW { background: #10b981; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; }
  th, td { border: 1px solid #334155; padding: 9px 10px; text-align: left; font-size: 0.88rem; vertical-align: top; }
  th { background: #0f172a; color: #94a3b8; }
  a { color: #7dd3fc; text-decoration: none; word-break: break-all; }
  a:hover { text-decoration: underline; }
  .alert { background: #7f1d1d; color: #fecaca; padding: 12px; border-radius: 8px; margin-bottom: 16px; }
  .meta-box { font-size: 0.84rem; color: #cbd5e1; line-height: 1.45; }
  .footer { text-align: center; color: #64748b; font-size: 0.82rem; margin-top: 24px; }
</style>
</head>
<body>
<div class="container">
  <div class="topbar">
    <h1>Automated OSINT Tool — Digital Footprint &amp; Social Media Recon</h1>
    <p>Python + Flask Local Web UI | Requests &amp; BeautifulSoup | SQLite Database Storage (osint_recon.db)</p>
  </div>

  {% if error %}
  <div class="alert">{{ error }}</div>
  {% endif %}

  <div class="card" style="margin-bottom: 20px;">
    <h2>Launch New Reconnaissance Scan</h2>
    <form method="POST" action="{{ url_for('scan') }}">
      <div class="form-row">
        <div class="form-group">
          <label>Target Username (Social Media Recon)</label>
          <input type="text" name="username" placeholder="e.g. torvalds" value="{{ default_user or '' }}">
        </div>
        <div class="form-group">
          <label>Target Domain or Email (Optional / Auto-Pivot)</label>
          <input type="text" name="domain" placeholder="e.g. kernel.org (leave blank to auto-pivot)" value="{{ default_domain or '' }}">
        </div>
      </div>
      <div style="margin-bottom: 14px;">
        <label style="display:inline; font-weight:normal;">
          <input type="checkbox" name="auto_pivot" checked>
          Automatically pivot to run WHOIS/DNS recon on websites discovered in social profiles
        </label>
      </div>
      <button type="submit" class="btn">Run Automated OSINT Scan</button>
    </form>
  </div>

  {% if active_scan %}
  {% set payload = active_scan.payload %}
  {% set exp = payload.exposure_summary %}
  <div class="card" style="margin-bottom: 20px; border-left: 5px solid #38bdf8;">
    <h2>Scan Result #{{ active_scan.id }} — Target: {{ payload.target_label }}</h2>
    <p>
      <strong>Generated:</strong> {{ payload.generated_utc }} &nbsp;|&nbsp;
      <strong>Digital Exposure Level:</strong>
      <span class="badge {{ exp.exposure_level }}">{{ exp.exposure_level }} ({{ exp.exposure_score }}/100)</span>
    </p>
    <ul>
      {% for note in exp.observations %}
      <li>{{ note }}</li>
      {% endfor %}
    </ul>
    <p>
      <a class="btn btn-sm" href="{{ url_for('download_report', scan_id=active_scan.id, fmt='html') }}" target="_blank">Open Standalone HTML Report</a>
      <a class="btn btn-sm btn-outline" href="{{ url_for('download_report', scan_id=active_scan.id, fmt='json') }}">Download JSON</a>
      <a class="btn btn-sm btn-outline" href="{{ url_for('download_report', scan_id=active_scan.id, fmt='txt') }}">Download TXT</a>
    </p>

    {% if payload.username_recon %}
    {% set u = payload.username_recon %}
    <h3>Social Media Reconnaissance (@{{ u.target_username }}) — Found {{ u.accounts_found }}/{{ u.platforms_checked }} in {{ u.execution_time_sec }}s</h3>
    <table>
      <thead>
        <tr><th>Platform</th><th>Category</th><th>Profile URL</th><th>Latency</th><th>Extracted Public Metadata</th></tr>
      </thead>
      <tbody>
        {% for item in u.results if item.status == 'FOUND' %}
        <tr>
          <td><strong>{{ item.platform }}</strong></td>
          <td>{{ item.category }}</td>
          <td><a href="{{ item.url }}" target="_blank">{{ item.url }}</a></td>
          <td>{{ item.response_time_ms }} ms</td>
          <td class="meta-box">
            {% if item.metadata %}
              {% for k, v in item.metadata.items() %}
                <strong>{{ k }}:</strong> {{ v }}<br>
              {% endfor %}
            {% else %}
              <em>None</em>
            {% endif %}
          </td>
        </tr>
        {% else %}
        <tr><td colspan="5">No public accounts matched this username on checked platforms.</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}

    {% if payload.domain_recon %}
    {% set d = payload.domain_recon %}
    <h3 style="margin-top:20px;">Domain &amp; Infrastructure Footprint ({{ d.target_domain }}) — IP: {{ d.ip_address }} ({{ d.execution_time_sec }}s)</h3>
    <p>
      <strong>Email Security:</strong>
      MX={{ d.email_security.has_mx }} |
      SPF={{ d.email_security.has_spf }} |
      DMARC={{ d.email_security.has_dmarc }}
    </p>
    <table>
      <thead><tr><th>Category</th><th>Key / Record</th><th>Value</th></tr></thead>
      <tbody>
        {% for k, v in d.whois.items() %}
        <tr><td>WHOIS</td><td><strong>{{ k }}</strong></td><td>{{ v }}</td></tr>
        {% endfor %}
        {% for rtype, recs in d.dns_records.items() if recs %}
        <tr><td>DNS</td><td><strong>{{ rtype }}</strong></td><td>{{ recs[:4]|join(', ') }}</td></tr>
        {% endfor %}
        {% for k, v in d.http_headers.items() %}
        <tr><td>HTTP Header</td><td><strong>{{ k }}</strong></td><td>{{ v }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}
  </div>
  {% endif %}

  <div class="card">
    <h2>SQLite Database Scan History (osint_recon.db)</h2>
    <table>
      <thead>
        <tr><th>ID</th><th>Timestamp (UTC)</th><th>Target</th><th>Username</th><th>Domain</th><th>Found</th><th>Exposure</th><th>Action</th></tr>
      </thead>
      <tbody>
        {% for s in scans %}
        <tr>
          <td>#{{ s.id }}</td>
          <td>{{ s.created_utc }}</td>
          <td><strong>{{ s.target_label }}</strong></td>
          <td>{{ s.username or '—' }}</td>
          <td>{{ s.domain or '—' }}</td>
          <td>{{ s.accounts_found }}/{{ s.platforms_checked }}</td>
          <td><span class="badge {{ s.exposure_level }}">{{ s.exposure_level }} ({{ s.exposure_score }})</span></td>
          <td><a class="btn btn-sm" href="{{ url_for('index', scan_id=s.id) }}">View</a></td>
        </tr>
        {% else %}
        <tr><td colspan="8">No scans recorded in SQLite database yet. Run a scan above!</td></tr>
        {% endfor %}
      </tbody>
    </table>
  </div>

  <div class="footer">
    Automated OSINT Tool | Ethical Passive Reconnaissance Only | Cross-Platform (Windows &amp; Linux)
  </div>
</div>
</body>
</html>
"""


@app.route("/")
def index():
    scan_id = request.args.get("scan_id", type=int)
    scans = get_recent_scans(limit=25)
    active_scan = None
    if scan_id:
        active_scan = get_scan_by_id(scan_id)
    elif scans:
        active_scan = get_scan_by_id(scans[0]["id"])
    return render_template_string(TEMPLATE, scans=scans, active_scan=active_scan, error=None)


@app.route("/scan", methods=["POST"])
def scan():
    username = (request.form.get("username") or "").strip().lstrip("@")
    domain = (request.form.get("domain") or "").strip()
    auto_pivot = request.form.get("auto_pivot") is not None

    if not username and not domain:
        scans = get_recent_scans(limit=25)
        return render_template_string(
            TEMPLATE,
            scans=scans,
            active_scan=None,
            error="Please enter at least a target username or a domain.",
        )

    username_data = None
    domain_data = None

    if username:
        username_data = run_username_recon(username, max_workers=10)
        if not domain and auto_pivot and username_data.get("discovered_websites"):
            candidate = normalize_domain(username_data["discovered_websites"][0])
            if candidate and "." in candidate:
                domain = candidate

    if domain:
        clean_dom = normalize_domain(domain)
        if clean_dom:
            domain_data = run_domain_recon(clean_dom)

    parts = []
    if username_data:
        parts.append(username_data["target_username"])
    if domain_data:
        parts.append(domain_data["target_domain"])
    target_label = "_".join(parts) or "target"

    saved = save_reports(
        target_label=target_label,
        username_data=username_data,
        domain_data=domain_data,
    )
    return redirect(url_for("index", scan_id=saved["scan_id"]))


@app.route("/report/<int:scan_id>/<fmt>")
def download_report(scan_id, fmt):
    record = get_scan_by_id(scan_id)
    if not record:
        return "Scan not found", 404
    path_map = {
        "html": record.get("html_path"),
        "json": record.get("json_path"),
        "txt": record.get("txt_path"),
    }
    file_path = path_map.get(fmt)
    if not file_path or not os.path.isfile(file_path):
        return "Report file not found on disk", 404
    if fmt == "html":
        return send_file(file_path, mimetype="text/html")
    return send_file(file_path, as_attachment=True)


if __name__ == "__main__":
    print("=" * 65)
    print("  FLASK OSINT WEB INTERFACE RUNNING AT: http://127.0.0.1:5000")
    print("  Press CTRL+C to stop the server.")
    print("=" * 65)
    app.run(host="127.0.0.1", port=5000, debug=False)
