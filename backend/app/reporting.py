from datetime import datetime
from html import escape

from sqlalchemy.orm import Session

from .models import (
    Scan,
    Finding,
    Probe,
    MLPrediction,
    AgentTrace,
    Endpoint,
)


def build_report(db: Session, scan_id: int):
    """
    Build a complete structured report for one scan.
    """

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    if scan is None:
        raise ValueError("Scan not found.")

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .order_by(Finding.id.asc())
        .all()
    )

    probes = (
        db.query(Probe)
        .filter(Probe.scan_id == scan_id)
        .order_by(Probe.id.asc())
        .all()
    )

    traces = (
        db.query(AgentTrace)
        .filter(AgentTrace.scan_id == scan_id)
        .order_by(
            AgentTrace.step.asc(),
            AgentTrace.id.asc(),
        )
        .all()
    )

    predictions = (
        db.query(MLPrediction)
        .join(
            Endpoint,
            MLPrediction.endpoint_id == Endpoint.id,
        )
        .all()
    )

    confirmed_findings = [
        finding
        for finding in findings
        if finding.confirmed
    ]

    high_count = sum(
        1
        for finding in confirmed_findings
        if finding.severity == "HIGH"
    )

    medium_count = sum(
        1
        for finding in confirmed_findings
        if finding.severity == "MEDIUM"
    )

    low_count = sum(
        1
        for finding in confirmed_findings
        if finding.severity == "LOW"
    )

    report = {
        "metadata": {
            "product": "SentinelAPI",
            "report_type": (
                "Zero-Trust API Authorization Scan"
            ),
            "scan_id": scan.id,
            "generated_at": datetime.utcnow().isoformat(),
        },

        "scan": {
            "name": scan.name,
            "target": scan.target,
            "status": scan.status,
            "created_at": (
                scan.created_at.isoformat()
                if scan.created_at
                else None
            ),
        },

        "summary": {
            "total_findings": len(findings),
            "confirmed_findings": len(
                confirmed_findings
            ),
            "high": high_count,
            "medium": medium_count,
            "low": low_count,
            "total_probes": len(probes),
            "agent_steps": len(traces),
            "ml_predictions": len(predictions),
        },

        "findings": [
            {
                "id": finding.id,
                "endpoint_id": finding.endpoint_id,
                "type": finding.vulnerability_type,
                "severity": finding.severity,
                "title": finding.title,
                "description": finding.description,
                "evidence": finding.evidence,
                "confirmed": finding.confirmed,
            }
            for finding in findings
        ],

        "probes": [
            {
                "id": probe.id,
                "endpoint_id": probe.endpoint_id,
                "owner_identity": probe.identity_a,
                "test_identity": probe.identity_b,
                "owner_status": probe.status_code_a,
                "test_identity_status": (
                    probe.status_code_b
                ),
            }
            for probe in probes
        ],

        "ml_predictions": [
            {
                "endpoint_id": prediction.endpoint_id,
                "probability": prediction.probability,
                "priority": prediction.priority,
                "model_version": (
                    prediction.model_version
                ),
            }
            for prediction in predictions
        ],

        "agent_trace": [
            {
                "step": trace.step,
                "phase": trace.phase,
                "action": trace.action,
                "target": trace.target,
                "observation": trace.observation,
                "decision": trace.decision,
                "result": trace.result,
            }
            for trace in traces
        ],

        "limitations": [
            "Testing is restricted to authorized "
            "and allowlisted targets.",
            "Current automated authorization testing "
            "focuses on BOLA.",
            "ML predictions are used for candidate "
            "prioritization only.",
            "Vulnerability confirmation is performed "
            "through deterministic authorization "
            "evidence.",
            "A scan with no confirmed finding does not "
            "prove that the complete API is secure.",
        ],
    }

    return report


def report_to_html(report: dict) -> str:
    """
    Convert structured report into a standalone HTML report.
    """

    metadata = report["metadata"]
    scan = report["scan"]
    summary = report["summary"]

    findings_html = ""

    if report["findings"]:

        for finding in report["findings"]:

            severity = escape(
                str(finding["severity"] or "INFO")
            )

            findings_html += f"""
            <div class="finding">
                <div class="finding-header">
                    <h3>
                        {escape(
                            str(
                                finding["title"]
                                or finding["type"]
                            )
                        )}
                    </h3>
                    <span class="severity">
                        {severity}
                    </span>
                </div>

                <p>
                    {escape(
                        str(
                            finding["description"]
                            or ""
                        )
                    )}
                </p>

                <pre>{escape(
                    str(
                        finding["evidence"]
                        or ""
                    )
                )}</pre>
            </div>
            """

    else:

        findings_html = """
        <div class="empty">
            No confirmed BOLA finding was produced
            within the tested scope.
        </div>
        """

    trace_rows = ""

    for trace in report["agent_trace"]:

        trace_rows += f"""
        <tr>
            <td>{trace["step"]}</td>
            <td>{escape(
                str(trace["phase"] or "")
            )}</td>
            <td>{escape(
                str(trace["action"] or "")
            )}</td>
            <td>{escape(
                str(trace["target"] or "")
            )}</td>
            <td>{escape(
                str(trace["result"] or "")
            )}</td>
        </tr>
        """

    probe_rows = ""

    for probe in report["probes"]:

        probe_rows += f"""
        <tr>
            <td>{probe["endpoint_id"]}</td>
            <td>{escape(
                str(probe["owner_identity"])
            )}</td>
            <td>{probe["owner_status"]}</td>
            <td>{escape(
                str(probe["test_identity"])
            )}</td>
            <td>{probe["test_identity_status"]}</td>
        </tr>
        """

    return f"""
<!DOCTYPE html>
<html lang="en">

<head>

<meta charset="UTF-8">

<title>
SentinelAPI Security Report #{metadata["scan_id"]}
</title>

<style>

body {{
    margin: 0;
    padding: 40px;
    background: #050810;
    color: #e8edf7;
    font-family: Arial, sans-serif;
}}

.container {{
    max-width: 1100px;
    margin: auto;
}}

h1 {{
    margin-bottom: 5px;
}}

.subtitle {{
    color: #8d99ad;
}}

.grid {{
    display: grid;
    grid-template-columns:
        repeat(4, 1fr);
    gap: 15px;
    margin: 30px 0;
}}

.card {{
    background: #0d1422;
    border: 1px solid #202d42;
    border-radius: 10px;
    padding: 20px;
}}

.card strong {{
    display: block;
    font-size: 28px;
    margin-top: 8px;
}}

.section {{
    margin-top: 35px;
}}

.finding {{
    background: #0d1422;
    border: 1px solid #542d35;
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 15px;
}}

.finding-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
}}

.severity {{
    background: #7f1d1d;
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 12px;
}}

pre {{
    background: #050810;
    padding: 15px;
    overflow-x: auto;
    border-radius: 7px;
    color: #b8c5d9;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: #0d1422;
}}

th,
td {{
    padding: 12px;
    border-bottom: 1px solid #202d42;
    text-align: left;
}}

th {{
    color: #9ca9bd;
}}

.empty {{
    background: #0d1422;
    border: 1px solid #26364e;
    padding: 20px;
    border-radius: 10px;
}}

.footer {{
    margin-top: 50px;
    padding-top: 20px;
    border-top: 1px solid #202d42;
    color: #69778d;
    font-size: 12px;
}}

</style>

</head>

<body>

<div class="container">

<h1>SentinelAPI</h1>

<div class="subtitle">
Zero-Trust API Authorization Security Report
</div>

<div class="section">

<p>
<strong>Scan ID:</strong>
{metadata["scan_id"]}
</p>

<p>
<strong>Target:</strong>
{escape(str(scan["target"]))}
</p>

<p>
<strong>Status:</strong>
{escape(str(scan["status"]))}
</p>

<p>
<strong>Generated:</strong>
{metadata["generated_at"]}
</p>

</div>


<div class="grid">

<div class="card">
Total Findings
<strong>
{summary["total_findings"]}
</strong>
</div>

<div class="card">
Confirmed
<strong>
{summary["confirmed_findings"]}
</strong>
</div>

<div class="card">
High Severity
<strong>
{summary["high"]}
</strong>
</div>

<div class="card">
BOLA Probes
<strong>
{summary["total_probes"]}
</strong>
</div>

</div>


<div class="section">

<h2>Findings</h2>

{findings_html}

</div>


<div class="section">

<h2>Authorization Probes</h2>

<table>

<thead>

<tr>
<th>Endpoint</th>
<th>Owner</th>
<th>Owner Status</th>
<th>Test Identity</th>
<th>Test Status</th>
</tr>

</thead>

<tbody>

{probe_rows}

</tbody>

</table>

</div>


<div class="section">

<h2>Agent Activity</h2>

<table>

<thead>

<tr>
<th>Step</th>
<th>Phase</th>
<th>Action</th>
<th>Target</th>
<th>Result</th>
</tr>

</thead>

<tbody>

{trace_rows}

</tbody>

</table>

</div>


<div class="section">

<h2>Scope & Limitations</h2>

<ul>

{
"".join(
    f"<li>{escape(str(item))}</li>"
    for item in report["limitations"]
)
}

</ul>

</div>


<div class="footer">

Generated by SentinelAPI.
ML prioritization is advisory; vulnerability
confirmation is evidence-driven.

</div>

</div>

</body>

</html>
"""