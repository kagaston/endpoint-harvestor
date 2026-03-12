from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Template

from reporters.types import ReportData
from logger import get_logger

log = get_logger("reporters.html")

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IntrusionInspector — {{ case_id or 'Report' }}</title>
<style>
:root {
    --bg-primary: #111827;
    --bg-secondary: #1f2937;
    --bg-tertiary: #374151;
    --bg-card: #1e293b;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --border-color: #334155;
    --accent: #3b82f6;
    --accent-dim: #1e3a5f;
    --severity-critical: #dc2626;
    --severity-high: #ea580c;
    --severity-medium: #ca8a04;
    --severity-low: #0891b2;
    --severity-info: #6b7280;
    --font-sans: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    --font-mono: 'SF Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace;
    --radius: 8px;
    --transition: 0.2s ease;
}
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
html { scroll-behavior: smooth; }
body {
    font-family: var(--font-sans);
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
    min-height: 100vh;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }

/* NAV */
.top-nav {
    position: sticky; top: 0; z-index: 100;
    background: rgba(17,24,39,.92);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--border-color);
    padding: 0.75rem 2rem;
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem;
}
.top-nav .brand { font-weight: 700; font-size: 1.1rem; letter-spacing: -0.02em; }
.top-nav .brand span { color: var(--accent); }
.top-nav .meta { font-size: 0.82rem; color: var(--text-secondary); display: flex; gap: 1.5rem; flex-wrap: wrap; }
.nav-links { display: flex; gap: 0.25rem; flex-wrap: wrap; }
.nav-links a {
    font-size: 0.78rem; padding: 0.3rem 0.6rem; border-radius: 4px;
    color: var(--text-secondary); transition: background var(--transition), color var(--transition);
}
.nav-links a:hover { background: var(--bg-tertiary); color: var(--text-primary); text-decoration: none; }

/* LAYOUT */
.container { max-width: 1400px; margin: 0 auto; padding: 1.5rem 2rem 3rem; }
section { margin-bottom: 2rem; }
h2 {
    font-size: 1.25rem; font-weight: 600; margin-bottom: 1rem;
    padding-bottom: 0.5rem; border-bottom: 1px solid var(--border-color);
}

/* CARDS / PANELS */
.card {
    background: var(--bg-secondary); border: 1px solid var(--border-color);
    border-radius: var(--radius); padding: 1.25rem; margin-bottom: 0.75rem;
}

/* SUMMARY GRID */
.summary-grid {
    display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1rem; margin-bottom: 1.5rem;
}

/* RISK GAUGE */
.risk-gauge { position: relative; }
.risk-bar-track {
    width: 100%; height: 20px; background: var(--bg-tertiary);
    border-radius: 10px; overflow: hidden; margin: 0.75rem 0;
}
.risk-bar-fill {
    height: 100%; border-radius: 10px;
    transition: width 0.6s ease;
}
.risk-label { font-size: 2rem; font-weight: 700; }
.risk-descriptor { font-size: 0.9rem; font-weight: 600; }

/* SEVERITY BADGES */
.badge {
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 4px;
    font-size: 0.72rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em;
    line-height: 1.4;
}
.badge-critical { background: var(--severity-critical); color: #fff; }
.badge-high { background: var(--severity-high); color: #fff; }
.badge-medium { background: var(--severity-medium); color: #000; }
.badge-low { background: var(--severity-low); color: #fff; }
.badge-info { background: var(--severity-info); color: #fff; }
.count-row { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-top: 0.75rem; }
.count-pill {
    display: flex; align-items: center; gap: 0.35rem;
    padding: 0.3rem 0.65rem; border-radius: 6px; font-size: 0.82rem;
    background: var(--bg-tertiary);
}
.count-pill .dot {
    width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0;
}

/* TABLES */
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th {
    text-align: left; padding: 0.6rem 0.75rem; font-weight: 600; font-size: 0.78rem;
    text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-secondary);
    background: var(--bg-tertiary); border-bottom: 2px solid var(--border-color);
    position: sticky; top: 0;
}
td {
    padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border-color);
    vertical-align: top;
}
tr:nth-child(even) td { background: rgba(255,255,255,.02); }
tr:hover td { background: rgba(59,130,246,.06); }
.mono { font-family: var(--font-mono); font-size: 0.8rem; }
.table-wrap { overflow-x: auto; border-radius: var(--radius); border: 1px solid var(--border-color); }

/* DETAILS / COLLAPSIBLE */
details {
    border: 1px solid var(--border-color); border-radius: var(--radius);
    margin-bottom: 0.5rem; overflow: hidden;
    transition: border-color var(--transition);
}
details[open] { border-color: var(--accent); }
summary {
    cursor: pointer; padding: 0.75rem 1rem; background: var(--bg-secondary);
    font-weight: 500; display: flex; align-items: center; gap: 0.75rem;
    list-style: none; user-select: none;
    transition: background var(--transition);
}
summary:hover { background: var(--bg-tertiary); }
summary::-webkit-details-marker { display: none; }
summary::before {
    content: '\25B6'; font-size: 0.65rem; transition: transform var(--transition);
    color: var(--text-muted); flex-shrink: 0;
}
details[open] > summary::before { transform: rotate(90deg); }
.details-body { padding: 1rem; background: var(--bg-primary); }

/* FINDING CARDS */
.finding-header { flex: 1; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
.finding-title { font-weight: 600; }
.finding-meta { font-size: 0.78rem; color: var(--text-secondary); margin-top: 0.5rem; }
.finding-desc { margin: 0.75rem 0; color: var(--text-secondary); font-size: 0.88rem; line-height: 1.7; }
.evidence-block {
    background: var(--bg-secondary); border: 1px solid var(--border-color);
    border-radius: 6px; padding: 0.75rem; margin-top: 0.75rem;
    font-family: var(--font-mono); font-size: 0.78rem; overflow-x: auto;
    white-space: pre-wrap; word-break: break-all; color: var(--text-secondary);
}
.mitre-tags { display: flex; gap: 0.35rem; flex-wrap: wrap; margin-top: 0.5rem; }
.mitre-tag {
    font-size: 0.72rem; padding: 0.15rem 0.45rem; border-radius: 4px;
    background: var(--accent-dim); color: var(--accent); border: 1px solid var(--accent);
}

/* MITRE MATRIX */
.mitre-matrix { display: flex; gap: 2px; overflow-x: auto; padding-bottom: 0.5rem; }
.tactic-col { min-width: 150px; flex: 1; }
.tactic-header {
    padding: 0.5rem; text-align: center; font-size: 0.72rem; font-weight: 700;
    text-transform: uppercase; letter-spacing: 0.04em;
    background: var(--bg-tertiary); border-radius: 4px 4px 0 0;
    color: var(--text-secondary);
}
.tactic-cells { display: flex; flex-direction: column; gap: 2px; margin-top: 2px; }
.tech-cell {
    padding: 0.4rem 0.5rem; border-radius: 3px; font-size: 0.72rem;
    border-left: 3px solid transparent; background: var(--bg-secondary);
    transition: transform var(--transition), box-shadow var(--transition);
}
.tech-cell:hover { transform: translateY(-1px); box-shadow: 0 2px 8px rgba(0,0,0,.3); }
.tech-cell .tid { font-weight: 700; font-family: var(--font-mono); }
.tech-cell .tname { color: var(--text-secondary); display: block; margin-top: 1px; }
.tech-cell.sev-critical { border-left-color: var(--severity-critical); background: rgba(220,38,38,.12); }
.tech-cell.sev-high { border-left-color: var(--severity-high); background: rgba(234,88,12,.10); }
.tech-cell.sev-medium { border-left-color: var(--severity-medium); background: rgba(202,138,4,.10); }
.tech-cell.sev-low { border-left-color: var(--severity-low); background: rgba(8,145,178,.10); }
.tech-cell.sev-info { border-left-color: var(--severity-info); background: rgba(107,114,128,.10); }

/* SEARCH / FILTER BAR */
.filter-bar {
    display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; align-items: center;
}
.filter-bar input[type="text"] {
    flex: 1; min-width: 200px; padding: 0.5rem 0.75rem;
    background: var(--bg-tertiary); border: 1px solid var(--border-color);
    border-radius: 6px; color: var(--text-primary); font-size: 0.85rem;
    outline: none; transition: border-color var(--transition);
}
.filter-bar input[type="text"]:focus { border-color: var(--accent); }
.filter-bar select {
    padding: 0.5rem 0.75rem; background: var(--bg-tertiary);
    border: 1px solid var(--border-color); border-radius: 6px;
    color: var(--text-primary); font-size: 0.85rem; outline: none;
}
.btn {
    padding: 0.45rem 0.85rem; border: 1px solid var(--border-color);
    border-radius: 6px; background: var(--bg-tertiary); color: var(--text-primary);
    font-size: 0.82rem; cursor: pointer; transition: background var(--transition);
}
.btn:hover { background: var(--bg-secondary); }

/* HIGHLIGHT ROW */
.row-suspicious td { background: rgba(220,38,38,.08) !important; }

/* FOOTER */
.report-footer {
    text-align: center; padding: 2rem 0 1rem; font-size: 0.78rem;
    color: var(--text-muted); border-top: 1px solid var(--border-color);
    margin-top: 2rem;
}
</style>
</head>
<body>

<!-- NAV -->
<nav class="top-nav">
    <div>
        <div class="brand"><span>Intrusion</span>Inspector</div>
        <div class="meta">
            {% if case_id %}<span>Case: {{ case_id }}</span>{% endif %}
            {% if examiner %}<span>Examiner: {{ examiner }}</span>{% endif %}
            <span>Generated: {{ generated_at }}</span>
        </div>
    </div>
    <div class="nav-links">
        <a href="#summary">Summary</a>
        <a href="#mitre">MITRE</a>
        <a href="#findings">Findings</a>
        <a href="#system">System</a>
        <a href="#processes">Processes</a>
        <a href="#network">Network</a>
        <a href="#persistence">Persistence</a>
        <a href="#timeline">Timeline</a>
        <a href="#collectors">Collectors</a>
        <a href="#" onclick="toggleAllSections(event)">Toggle All</a>
    </div>
</nav>

<div class="container">

<!-- EXECUTIVE SUMMARY -->
<section id="summary">
<h2>Executive Summary</h2>
<div class="summary-grid">
    <div class="card risk-gauge">
        <div style="color:var(--text-secondary);font-size:0.82rem;text-transform:uppercase;letter-spacing:.06em;font-weight:600;">Risk Score</div>
        <div style="display:flex;align-items:baseline;gap:0.5rem;margin-top:0.25rem;">
            <span class="risk-label" style="color:{{ risk_color }};">{{ risk_score }}</span>
            <span class="risk-descriptor" style="color:{{ risk_color }};">/ 100 — {{ risk_label }}</span>
        </div>
        <div class="risk-bar-track">
            <div class="risk-bar-fill" style="width:{{ risk_score }}%;background:{{ risk_color }};"></div>
        </div>
    </div>
    <div class="card">
        <div style="color:var(--text-secondary);font-size:0.82rem;text-transform:uppercase;letter-spacing:.06em;font-weight:600;">Findings</div>
        <div style="font-size:2rem;font-weight:700;margin-top:0.25rem;">{{ total_findings }}</div>
        <div class="count-row">
            {% for sev in severity_order %}
            <div class="count-pill">
                <span class="dot" style="background:var(--severity-{{ sev }});"></span>
                {{ findings_by_severity[sev] | length }} {{ sev }}
            </div>
            {% endfor %}
        </div>
    </div>
    <div class="card">
        <div style="color:var(--text-secondary);font-size:0.82rem;text-transform:uppercase;letter-spacing:.06em;font-weight:600;">Target System</div>
        <div style="font-size:1.1rem;font-weight:600;margin-top:0.5rem;">{{ system_info.get('hostname', 'Unknown') }}</div>
        <div style="color:var(--text-secondary);font-size:0.88rem;">{{ system_info.get('os', 'Unknown OS') }}</div>
        {% if system_info.get('architecture') %}
        <div style="color:var(--text-muted);font-size:0.82rem;margin-top:0.25rem;">{{ system_info.get('architecture') }}</div>
        {% endif %}
    </div>
</div>
</section>

<!-- MITRE ATT&CK MATRIX -->
{% if mitre_summary and mitre_summary.get('tactics') %}
<section id="mitre">
<h2>MITRE ATT&amp;CK Coverage ({{ mitre_summary.get('technique_count', 0) }} techniques)</h2>
<div class="mitre-matrix">
    {% for tactic, tids in mitre_summary['tactics'].items() %}
    <div class="tactic-col">
        <div class="tactic-header">{{ tactic }}</div>
        <div class="tactic-cells">
            {% for tid in tids %}
            {% set tech = mitre_summary['techniques'].get(tid, {}) %}
            {% set tech_data = tech.get('technique', {}) %}
            {% set sev = tech.get('max_severity', 'info') %}
            <div class="tech-cell sev-{{ sev }}" title="{{ tech_data.get('name', tid) }} ({{ tech.get('finding_count', 0) }} findings, {{ sev }})">
                <span class="tid">{{ tid }}</span>
                <span class="tname">{{ tech_data.get('name', '') }}</span>
            </div>
            {% endfor %}
        </div>
    </div>
    {% endfor %}
</div>
</section>
{% endif %}

<!-- FINDINGS -->
<section id="findings">
<h2>Findings ({{ total_findings }})</h2>
{% for sev in severity_order %}
{% set sev_findings = findings_by_severity[sev] %}
{% if sev_findings %}
<details {% if sev in ('critical', 'high') %}open{% endif %}>
<summary>
    <div class="finding-header">
        <span class="badge badge-{{ sev }}">{{ sev }}</span>
        <span>{{ sev_findings | length }} finding{{ 's' if sev_findings | length != 1 else '' }}</span>
    </div>
</summary>
<div class="details-body">
{% for finding in sev_findings %}
<details {% if sev == 'critical' %}open{% endif %} style="margin-bottom:0.5rem;">
<summary>
    <div class="finding-header">
        <span class="badge badge-{{ finding.severity.value }}">{{ finding.severity.value }}</span>
        <span class="finding-title">{{ finding.title }}</span>
    </div>
</summary>
<div class="details-body">
    <div class="finding-desc">{{ finding.description }}</div>
    <div class="finding-meta">
        <strong>Source:</strong> {{ finding.source }}&nbsp;&nbsp;
        <strong>Analyzer:</strong> {{ finding.analyzer }}
        {% if finding.timestamp %}&nbsp;&nbsp;<strong>Time:</strong> {{ finding.timestamp }}{% endif %}
    </div>
    {% if finding.mitre_techniques %}
    <div class="mitre-tags">
        {% for t in finding.mitre_techniques %}
        <a class="mitre-tag" href="{{ t.url or '#' }}" target="_blank" rel="noopener" title="{{ t.tactic }}">{{ t.technique_id }}: {{ t.name }}</a>
        {% endfor %}
    </div>
    {% endif %}
    {% if finding.evidence %}
    <div class="evidence-block">{{ finding.evidence | tojson(indent=2) }}</div>
    {% endif %}
</div>
</details>
{% endfor %}
</div>
</details>
{% endif %}
{% endfor %}
{% if total_findings == 0 %}
<div class="card" style="text-align:center;color:var(--text-muted);">No findings detected.</div>
{% endif %}
</section>

<!-- SYSTEM OVERVIEW -->
{% if system_info %}
<section id="system">
<h2>System Overview</h2>
<details open>
<summary>System Information</summary>
<div class="details-body">
<div class="table-wrap">
<table>
<thead><tr><th>Field</th><th>Value</th></tr></thead>
<tbody>
{% for key, val in system_info.items() %}
{% if val is not mapping and val is not iterable or val is string %}
<tr><td style="font-weight:600;white-space:nowrap;">{{ key }}</td><td class="mono">{{ val }}</td></tr>
{% endif %}
{% endfor %}
{% if system_info.get('network_interfaces') is mapping %}
{% for iface, addrs in system_info['network_interfaces'].items() %}
<tr><td style="font-weight:600;">net: {{ iface }}</td><td class="mono">{{ addrs if addrs is string else addrs | tojson }}</td></tr>
{% endfor %}
{% endif %}
</tbody>
</table>
</div>
</div>
</details>
</section>
{% endif %}

<!-- PROCESSES -->
{% if process_artifacts %}
<section id="processes">
<h2>Processes ({{ process_artifacts | length }})</h2>
<details>
<summary>Process Table</summary>
<div class="details-body">
<div class="table-wrap">
<table>
<thead><tr><th>PID</th><th>Name</th><th>User</th><th>Parent</th><th>Command Line</th><th>Path</th></tr></thead>
<tbody>
{% for p in process_artifacts %}
{% set d = p.data %}
{% set suspicious = d.get('suspicious', false) or d.get('flagged', false) %}
<tr {% if suspicious %}class="row-suspicious"{% endif %}>
<td class="mono">{{ d.get('pid', '') }}</td>
<td>{{ d.get('name', '') }}</td>
<td>{{ d.get('username', d.get('user', '')) }}</td>
<td class="mono">{{ d.get('ppid', d.get('parent_pid', '')) }}</td>
<td class="mono" style="max-width:350px;overflow:hidden;text-overflow:ellipsis;" title="{{ d.get('cmdline', d.get('command_line', '')) }}">{{ d.get('cmdline', d.get('command_line', '')) }}</td>
<td class="mono" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;">{{ d.get('exe', d.get('exe_path', d.get('path', ''))) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</div>
</details>
</section>
{% endif %}

<!-- NETWORK CONNECTIONS -->
{% if network_artifacts %}
<section id="network">
<h2>Network Connections ({{ network_artifacts | length }})</h2>
<details>
<summary>Active Connections</summary>
<div class="details-body">
<div class="table-wrap">
<table>
<thead><tr><th>Local Address</th><th>Remote Address</th><th>Status</th><th>PID</th><th>Process</th></tr></thead>
<tbody>
{% for n in network_artifacts %}
{% set d = n.data %}
<tr>
<td class="mono">{{ d.get('local_address', d.get('local_addr', '')) }}{% if d.get('local_port') %}:{{ d.get('local_port') }}{% endif %}</td>
<td class="mono">{{ d.get('remote_address', d.get('remote_addr', '')) }}{% if d.get('remote_port') %}:{{ d.get('remote_port') }}{% endif %}</td>
<td>{{ d.get('status', d.get('state', '')) }}</td>
<td class="mono">{{ d.get('pid', '') }}</td>
<td>{{ d.get('process_name', d.get('process', d.get('name', ''))) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</div>
</details>
</section>
{% endif %}

<!-- PERSISTENCE -->
{% if persistence_artifacts %}
<section id="persistence">
<h2>Persistence Review ({{ persistence_artifacts | length }})</h2>
<details>
<summary>Scheduled Tasks, Services &amp; Startup Items</summary>
<div class="details-body">
<div class="table-wrap">
<table>
<thead><tr><th>Type</th><th>Name</th><th>Details</th><th>Status</th></tr></thead>
<tbody>
{% for item in persistence_artifacts %}
{% set d = item.data %}
<tr>
<td><span class="badge badge-info">{{ item.artifact_type.value | replace('_', ' ') }}</span></td>
<td style="font-weight:600;">{{ d.get('name', d.get('task_name', d.get('service_name', ''))) }}</td>
<td class="mono" style="max-width:400px;overflow:hidden;text-overflow:ellipsis;">{{ d.get('command', d.get('path', d.get('description', d.get('schedule', '')))) }}</td>
<td>{{ d.get('status', d.get('state', d.get('enabled', ''))) }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</div>
</details>
</section>
{% endif %}

<!-- TIMELINE -->
{% if timeline_entries %}
<section id="timeline">
<h2>Timeline ({{ timeline_entries | length }} events)</h2>
<div class="filter-bar">
    <input type="text" id="timeline-search" placeholder="Search timeline…" oninput="filterTimeline()">
    <select id="timeline-type-filter" onchange="filterTimeline()">
        <option value="">All Types</option>
        {% for etype in timeline_event_types %}
        <option value="{{ etype }}">{{ etype }}</option>
        {% endfor %}
    </select>
</div>
<div class="table-wrap">
<table id="timeline-table">
<thead><tr><th>Timestamp</th><th>Source</th><th>Type</th><th>Description</th></tr></thead>
<tbody>
{% for entry in timeline_entries %}
<tr data-type="{{ entry.event_type }}" data-searchable="{{ entry.timestamp }} {{ entry.source }} {{ entry.event_type }} {{ entry.description }}">
<td class="mono" style="white-space:nowrap;">{{ entry.timestamp }}</td>
<td>{{ entry.source }}</td>
<td><span class="badge badge-info">{{ entry.event_type }}</span></td>
<td>{{ entry.description }}</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</section>
{% endif %}

<!-- COLLECTION SUMMARY -->
{% if collector_results %}
<section id="collectors">
<h2>Collection Summary</h2>
<details open>
<summary>Collector Results ({{ collector_results | length }})</summary>
<div class="details-body">
<div class="table-wrap">
<table>
<thead><tr><th>Collector</th><th>Platform</th><th>Artifacts</th><th>Errors</th><th>Duration</th></tr></thead>
<tbody>
{% for c in collector_results %}
<tr>
<td style="font-weight:600;">{{ c.collector_name }}</td>
<td>{{ c.platform }}</td>
<td>{{ c.artifacts | length }}</td>
<td {% if c.errors %}style="color:var(--severity-critical);font-weight:600;"{% endif %}>{{ c.errors | length }}</td>
<td class="mono">{{ "%.0f" | format(c.duration_ms) }}ms</td>
</tr>
{% endfor %}
</tbody>
</table>
</div>
</div>
</details>
</section>
{% endif %}

<div class="report-footer">
    Generated by IntrusionInspector &mdash; {{ generated_at }}
</div>

</div><!-- /container -->

<script>
function filterTimeline() {
    var search = document.getElementById('timeline-search').value.toLowerCase();
    var typeFilter = document.getElementById('timeline-type-filter').value;
    var rows = document.querySelectorAll('#timeline-table tbody tr');
    for (var i = 0; i < rows.length; i++) {
        var row = rows[i];
        var matchType = !typeFilter || row.getAttribute('data-type') === typeFilter;
        var matchSearch = !search || (row.getAttribute('data-searchable') || '').toLowerCase().indexOf(search) !== -1;
        row.style.display = (matchType && matchSearch) ? '' : 'none';
    }
}

var allExpanded = false;
function toggleAllSections(e) {
    e.preventDefault();
    allExpanded = !allExpanded;
    var details = document.querySelectorAll('details');
    for (var i = 0; i < details.length; i++) {
        details[i].open = allExpanded;
    }
}
</script>
</body>
</html>"""


class HTMLReporter:
    @property
    def name(self) -> str:
        return "html"

    @property
    def display_name(self) -> str:
        return "HTML Report"

    def generate(self, data: ReportData, output_dir: Path) -> Path:
        output_dir.mkdir(parents=True, exist_ok=True)

        all_artifacts = [
            a for r in data.collector_results for a in r.artifacts
        ]

        process_artifacts = [
            a for a in all_artifacts if a.artifact_type.value == "process"
        ]
        network_artifacts = [
            a for a in all_artifacts
            if a.artifact_type.value == "network_connection"
        ]
        persistence_types = {"scheduled_task", "service", "startup_item", "cron_job"}
        persistence_artifacts = [
            a for a in all_artifacts
            if a.artifact_type.value in persistence_types
        ]

        timeline_entries: list = []
        for result in data.analysis_results:
            timeline_entries.extend(result.timeline_entries)
        timeline_entries.sort(key=lambda e: e.timestamp or "")

        timeline_event_types = sorted({e.event_type for e in timeline_entries})

        risk_score = data.risk_score
        if risk_score >= 70:
            risk_color, risk_label = "#dc2626", "CRITICAL"
        elif risk_score >= 40:
            risk_color, risk_label = "#ea580c", "HIGH"
        elif risk_score >= 20:
            risk_color, risk_label = "#ca8a04", "MEDIUM"
        elif risk_score >= 5:
            risk_color, risk_label = "#0891b2", "LOW"
        else:
            risk_color, risk_label = "#22c55e", "CLEAN"

        severity_order = ["critical", "high", "medium", "low", "info"]

        template = Template(_HTML_TEMPLATE)
        html = template.render(
            case_id=data.case_id,
            examiner=data.examiner,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            system_info=data.system_info,
            risk_score=risk_score,
            risk_color=risk_color,
            risk_label=risk_label,
            total_findings=len(data.all_findings),
            findings_by_severity=data.findings_by_severity,
            severity_order=severity_order,
            mitre_summary=data.mitre_summary,
            collector_results=data.collector_results,
            process_artifacts=process_artifacts,
            network_artifacts=network_artifacts,
            persistence_artifacts=persistence_artifacts,
            timeline_entries=timeline_entries,
            timeline_event_types=timeline_event_types,
        )

        report_path = output_dir / "report.html"
        report_path.write_text(html, encoding="utf-8")
        log.info("HTML report written to %s", report_path)
        return report_path
