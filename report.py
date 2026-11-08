"""PDF report generation with ReportLab."""
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

BAND_COLORS = {"LOW": colors.green, "MEDIUM": colors.gold, "HIGH": colors.orange, "CRITICAL": colors.red}


def build_pdf(scan: dict, path) -> str:
    ss = getSampleStyleSheet()
    doc = SimpleDocTemplate(str(path), pagesize=A4, title="ACASE Report")
    el = [Paragraph("ACASE - AiTM Security Assessment Report", ss["Title"]),
          Paragraph(f"Target: {scan['target']}<br/>Scanned: {scan['created_at']}<br/>"
                    f"Duration: {scan['scan_seconds']} s", ss["Normal"]), Spacer(1, 12)]

    t = Table([["Risk score", "Band", "Checks failed", "Weighted index"],
               [scan["risk_score"], scan["band"], f"{scan['checks_failed']}/{scan['checks_run']}",
                scan["weighted_index"]]])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E9C")),
                           ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                           ("BACKGROUND", (1, 1), (1, 1), BAND_COLORS.get(scan["band"], colors.grey)),
                           ("GRID", (0, 0), (-1, -1), 0.5, colors.grey), ("ALIGN", (0, 0), (-1, -1), "CENTER")]))
    el += [t, Spacer(1, 6), Paragraph(f"Required action: {scan['action']}", ss["Normal"]), Spacer(1, 12),
           Paragraph("Findings", ss["Heading2"])]

    rows = [["Module", "Check", "Weight", "Result"]]
    for f in scan["findings"]:
        rows.append([f["module"], Paragraph(f["title"], ss["BodyText"]), f["weight"],
                     "FAIL" if f["failed"] else "pass"])
    ft = Table(rows, colWidths=[80, 250, 50, 50], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F4E9C")),
             ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("GRID", (0, 0), (-1, -1), 0.25, colors.grey)]
    for i, f in enumerate(scan["findings"], 1):
        if f["failed"]:
            style.append(("BACKGROUND", (3, i), (3, i), colors.HexColor("#F8D7DA")))
    ft.setStyle(TableStyle(style))
    el += [ft, Spacer(1, 12), Paragraph("Details", ss["Heading2"])]
    for f in scan["findings"]:
        if f["failed"]:
            el.append(Paragraph(f"<b>{f['title']}</b>: {f['detail']}<br/><i>Fix:</i> {f['remediation']}", ss["BodyText"]))
            el.append(Spacer(1, 4))

    ai = scan.get("recommendations", {})
    el += [Spacer(1, 8), Paragraph(f"Recommendations ({ai.get('source', 'n/a')})", ss["Heading2"])]
    for line in (ai.get("text") or "").split("\n"):
        if line.strip():
            el.append(Paragraph(line.replace("&", "&amp;").replace("<", "&lt;"), ss["BodyText"]))
    el += [Spacer(1, 12), Paragraph("For authorised security assessment only.", ss["Italic"])]
    doc.build(el)
    return str(path)
