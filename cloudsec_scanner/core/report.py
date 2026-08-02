"""Turns a list of Findings into a saved report + posture score."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from cloudsec_scanner.core.finding import Finding, Severity


def compute_posture_score(findings: list[Finding]) -> int:
    """
    100 = clean scan. Uses asymptotic decay (100 / (1 + penalty/100))
    instead of linear subtraction, so the score degrades smoothly and
    a handful of criticals doesn't immediately floor at 0 -- it keeps
    differentiating "bad" from "catastrophic".
    """
    raw_penalty = sum(f.severity.weight for f in findings)
    score = round(100 / (1 + raw_penalty / 100))
    return max(1, min(100, score))


def build_report(findings: list[Finding], provider: str, account_id: str | None = None,
                  scan_duration_seconds: float | None = None) -> dict:
    by_severity = Counter(f.severity.value for f in findings)
    by_category = Counter(f.category.value for f in findings)
    by_resource_type = Counter(f.resource_type for f in findings)

    return {
        "meta": {
            "provider": provider,
            "account_id": account_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan_duration_seconds": scan_duration_seconds,
            "total_findings": len(findings),
        },
        "posture_score": compute_posture_score(findings),
        "summary": {
            "by_severity": {s.value: by_severity.get(s.value, 0) for s in Severity},
            "by_category": dict(by_category),
            "by_resource_type": dict(by_resource_type),
        },
        "findings": [f.to_dict() for f in findings],
    }


def save_json_report(report: dict, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(json.dumps(report, indent=2, default=str))
    return path


def save_html_report(report: dict, path: str | Path) -> Path:
    """Minimal static HTML export (no JS framework needed to view it)."""
    sev_colors = {
        "CRITICAL": "#E5484D", "HIGH": "#F5A623",
        "MEDIUM": "#4A9EFF", "LOW": "#6B7785", "INFO": "#39424E",
    }
    rows = []
    for f in sorted(report["findings"], key=lambda x: list(sev_colors).index(x["severity"])):
        rows.append(f"""
        <tr>
          <td><span class="badge" style="background:{sev_colors[f['severity']]}">{f['severity']}</span></td>
          <td>{f['category']}</td>
          <td>{f['resource_type']}</td>
          <td><code>{f['resource_id']}</code></td>
          <td>{f['region']}</td>
          <td>{f['description']}</td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CloudSec Scan Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#0B0F14; color:#E6EDF3; margin:0; padding:32px; }}
  h1 {{ font-weight:600; }}
  .meta {{ color:#7C8B9C; margin-bottom:24px; }}
  .score {{ font-size:48px; font-weight:700; }}
  table {{ width:100%; border-collapse:collapse; margin-top:24px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid #232C38; font-size:14px; }}
  th {{ color:#7C8B9C; font-weight:600; text-transform:uppercase; font-size:11px; letter-spacing:0.05em; }}
  .badge {{ padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; color:#0B0F14; }}
  code {{ color:#2DD4BF; }}
</style></head>
<body>
  <h1>CloudSec Scanner Report</h1>
  <div class="meta">Provider: {report['meta']['provider']} &middot; Account: {report['meta']['account_id']} &middot; Generated: {report['meta']['generated_at']}</div>
  <div class="score">{report['posture_score']}<span style="font-size:16px;color:#7C8B9C">/100 posture score</span></div>
  <table>
    <thead><tr><th>Severity</th><th>Category</th><th>Resource Type</th><th>Resource</th><th>Region</th><th>Description</th></tr></thead>
    <tbody>{''.join(rows)}</tbody>
  </table>
</body></html>"""
    path = Path(path)
    path.write_text(html)
    return path
