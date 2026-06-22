"""Report Generator — creates HTML/JSON/PDF vulnerability reports."""

import json
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from vulnhawk.core.scanner import Vulnerability

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnHawk Scan Report — {{ target }}</title>
    <style>
        :root {
            --bg: #0f172a;
            --surface: #1e293b;
            --border: #334155;
            --text: #e2e8f0;
            --text-dim: #94a3b8;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #06b6d4;
            --info: #6b7280;
            --accent: #8b5cf6;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
            padding: 2rem;
        }

        .container { max-width: 1000px; margin: 0 auto; }

        header {
            text-align: center;
            padding: 2rem 0;
            border-bottom: 1px solid var(--border);
            margin-bottom: 2rem;
        }

        h1 {
            font-size: 2rem;
            background: linear-gradient(135deg, #ef4444, #8b5cf6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }

        .meta { color: var(--text-dim); font-size: 0.9rem; }

        .summary {
            display: grid;
            grid-template-columns: repeat(5, 1fr);
            gap: 1rem;
            margin-bottom: 2rem;
        }

        .summary-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.2rem;
            text-align: center;
        }

        .summary-card .count {
            font-size: 2rem;
            font-weight: 700;
        }

        .summary-card .label {
            font-size: 0.8rem;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .critical .count { color: var(--critical); }
        .high .count { color: var(--high); }
        .medium .count { color: var(--medium); }
        .low .count { color: var(--low); }
        .info-card .count { color: var(--info); }

        .finding {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--border);
        }

        .finding.severity-CRITICAL { border-left-color: var(--critical); }
        .finding.severity-HIGH { border-left-color: var(--high); }
        .finding.severity-MEDIUM { border-left-color: var(--medium); }
        .finding.severity-LOW { border-left-color: var(--low); }
        .finding.severity-INFO { border-left-color: var(--info); }

        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
            flex-wrap: wrap;
            gap: 0.5rem;
        }

        .finding-title { font-size: 1.1rem; font-weight: 600; }

        .badges { display: flex; align-items: center; gap: 0.5rem; }

        .severity-badge {
            padding: 0.25rem 0.75rem;
            border-radius: 999px;
            font-size: 0.75rem;
            font-weight: 600;
            text-transform: uppercase;
        }

        .severity-badge.CRITICAL { background: rgba(239,68,68,0.2); color: var(--critical); }
        .severity-badge.HIGH { background: rgba(249,115,22,0.2); color: var(--high); }
        .severity-badge.MEDIUM { background: rgba(234,179,8,0.2); color: var(--medium); }
        .severity-badge.LOW { background: rgba(6,182,212,0.2); color: var(--low); }
        .severity-badge.INFO { background: rgba(107,114,128,0.2); color: var(--info); }

        .cvss-badge {
            padding: 0.25rem 0.6rem;
            border-radius: 6px;
            font-size: 0.72rem;
            font-weight: 700;
            font-family: monospace;
            letter-spacing: 0.03em;
        }

        .cvss-critical { background: rgba(239,68,68,0.15); color: #fca5a5; border: 1px solid rgba(239,68,68,0.3); }
        .cvss-high { background: rgba(249,115,22,0.15); color: #fdba74; border: 1px solid rgba(249,115,22,0.3); }
        .cvss-medium { background: rgba(234,179,8,0.15); color: #fde047; border: 1px solid rgba(234,179,8,0.3); }
        .cvss-low { background: rgba(6,182,212,0.15); color: #67e8f9; border: 1px solid rgba(6,182,212,0.3); }
        .cvss-info { background: rgba(107,114,128,0.15); color: #d1d5db; border: 1px solid rgba(107,114,128,0.3); }

        .finding-field { margin-bottom: 0.75rem; }
        .finding-field strong { color: var(--accent); font-size: 0.85rem; }
        .finding-field p { margin-top: 0.25rem; color: var(--text-dim); font-size: 0.9rem; }

        .evidence {
            background: var(--bg);
            padding: 0.75rem 1rem;
            border-radius: 8px;
            font-family: 'Cascadia Code', 'Fira Code', monospace;
            font-size: 0.85rem;
            overflow-x: auto;
        }

        footer {
            text-align: center;
            color: var(--text-dim);
            font-size: 0.8rem;
            padding: 2rem 0;
            border-top: 1px solid var(--border);
            margin-top: 2rem;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🦅 VulnHawk Scan Report</h1>
            <p class="meta">Target: <strong>{{ target }}</strong> | Scanned: {{ scan_date }} | Total Findings: {{ total }}</p>
        </header>

        <div class="summary">
            <div class="summary-card critical">
                <div class="count">{{ counts.CRITICAL }}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{{ counts.HIGH }}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{{ counts.MEDIUM }}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{{ counts.LOW }}</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info-card">
                <div class="count">{{ counts.INFO }}</div>
                <div class="label">Info</div>
            </div>
        </div>

        <h2 style="margin-bottom: 1rem; font-size: 1.3rem;">Detailed Findings</h2>

        {% for vuln in vulnerabilities %}
        <div class="finding severity-{{ vuln.severity }}">
            <div class="finding-header">
                <span class="finding-title">{{ vuln.title }}</span>
                <div class="badges">
                    {% if vuln.cvss_score is not none %}
                    <span class="cvss-badge cvss-{{ vuln.severity | lower }}">CVSS {{ "%.1f" | format(vuln.cvss_score) }}</span>
                    {% endif %}
                    <span class="severity-badge {{ vuln.severity }}">{{ vuln.severity }}</span>
                </div>
            </div>

            <div class="finding-field">
                <strong>URL</strong>
                <p>{{ vuln.url }}</p>
            </div>

            <div class="finding-field">
                <strong>Description</strong>
                <p>{{ vuln.description }}</p>
            </div>

            {% if vuln.evidence %}
            <div class="finding-field">
                <strong>Evidence</strong>
                <div class="evidence">{{ vuln.evidence }}</div>
            </div>
            {% endif %}

            <div class="finding-field">
                <strong>Remediation</strong>
                <p>{{ vuln.remediation }}</p>
            </div>

            {% if vuln.references %}
            <div class="finding-field">
                <strong>References</strong>
                {% for ref in vuln.references %}
                <p><a href="{{ ref }}" style="color: var(--accent);">{{ ref }}</a></p>
                {% endfor %}
            </div>
            {% endif %}

            {% if vuln.scanner_name %}
            <div class="finding-field">
                <strong>Detected By</strong>
                <p>{{ vuln.scanner_name }}</p>
            </div>
            {% endif %}
        </div>
        {% endfor %}

        {% if not vulnerabilities %}
        <div class="finding" style="text-align: center; border-left-color: #22c55e;">
            <p style="font-size: 1.2rem; color: #22c55e;">✅ No vulnerabilities found!</p>
            <p style="color: var(--text-dim); margin-top: 0.5rem;">
                The target appears to be secure against the tested attack vectors.
            </p>
        </div>
        {% endif %}

        <footer>
            Generated by VulnHawk v1.0.0 — Async Web Vulnerability Scanner<br>
            ⚠️ This report is for authorized testing only. Always get permission before scanning.
        </footer>
    </div>
</body>
</html>"""


def generate_html_report(
    vulnerabilities: list[Vulnerability],
    target: str,
    output_path: str,
) -> str:
    """
    Generate a beautiful HTML report from scan results.

    Args:
        vulnerabilities: List of discovered vulnerabilities
        target: Target URL that was scanned
        output_path: Path to save the HTML report

    Returns:
        Absolute path to the generated report
    """
    # Count by severity
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for vuln in vulnerabilities:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

    # Render template
    template = Template(HTML_TEMPLATE)
    html = template.render(
        target=target,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(vulnerabilities),
        counts=counts,
        vulnerabilities=vulnerabilities,
    )

    # Write report
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")

    return str(output.resolve())


def generate_json_report(
    vulnerabilities: list[Vulnerability],
    target: str,
    output_path: str,
) -> str:
    """Generate a JSON report from scan results."""
    report = {
        "target": target,
        "scan_date": datetime.now().isoformat(),
        "total_findings": len(vulnerabilities),
        "severity_counts": {
            sev: sum(1 for v in vulnerabilities if v.severity == sev)
            for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        },
        "findings": [
            {
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "url": v.url,
                "description": v.description,
                "evidence": v.evidence,
                "remediation": v.remediation,
                "scanner": v.scanner_name,
                "references": v.references,
            }
            for v in vulnerabilities
        ],
    }

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")

    return str(output.resolve())


def generate_pdf_report(
    vulnerabilities: list[Vulnerability],
    target: str,
    output_path: str,
) -> str:
    """
    Generate a PDF report by rendering the HTML template via WeasyPrint.

    Requires the 'pdf' optional dependency: pip install vulnhawk[pdf]

    Args:
        vulnerabilities: List of discovered vulnerabilities
        target: Target URL that was scanned
        output_path: Path to save the PDF report

    Returns:
        Absolute path to the generated PDF report

    Raises:
        ImportError: If weasyprint is not installed
    """
    try:
        from weasyprint import HTML as WeasyHTML
    except ImportError as exc:
        raise ImportError(
            "PDF export requires WeasyPrint. Install it with: pip install vulnhawk[pdf]"
        ) from exc

    # First generate the HTML content
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for vuln in vulnerabilities:
        counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

    template = Template(HTML_TEMPLATE)
    html_content = template.render(
        target=target,
        scan_date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        total=len(vulnerabilities),
        counts=counts,
        vulnerabilities=vulnerabilities,
    )

    # Convert to PDF
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    WeasyHTML(string=html_content).write_pdf(str(output))

    return str(output.resolve())
