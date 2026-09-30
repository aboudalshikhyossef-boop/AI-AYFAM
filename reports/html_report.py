"""
AI AYFAM v5 — Standalone Interactive HTML Report Generator
مولد تقارير HTML تفاعلية ومستقلة بالكامل (Zero-Dependency) بتصميم داكن حديث،
مقياس أمان SVG، رسوم بيانية خفيفة، وجداول قابلة للبحث والتصفية.
"""

import html
import json
from datetime import datetime
from typing import Dict, List, Any

def generate_interactive_html(scan_results: Dict[str, Any], hostname: str = "localhost") -> str:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    risk = scan_results.get("risk", {})
    score = risk.get("score", 100)
    grade = risk.get("grade", "A+")
    findings = scan_results.get("findings", [])
    counts = risk.get("counts", {})

    # لون المقياس حسب الدرجة
    gauge_color = "#10b981" if score >= 85 else "#f59e0b" if score >= 70 else "#ef4444"

    findings_json = []
    for f in findings:
        findings_json.append({
            "severity": f.get("severity", "info"),
            "title": html.escape(f.get("title", "")),
            "detail": html.escape(f.get("detail", "")),
            "fix": html.escape(f.get("fix", "")),
            "category": html.escape(f.get("category", "general")),
            "attack": ", ".join(f.get("attack_ids", [])),
        })

    html_content = f"""<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>تقرير AI AYFAM للأمن السيبراني — {html.escape(hostname)}</title>
<style>
:root {{
  --bg: #0f172a; --card: #1e293b; --border: #334155; --text: #f8fafc;
  --text-dim: #94a3b8; --accent: #06b6d4; --danger: #ef4444; --warning: #f59e0b; --success: #10b981;
}}
body {{ margin:0; padding:24px; background:var(--bg); color:var(--text); font-family:system-ui,-apple-system,sans-serif; }}
.header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid var(--border); padding-bottom:16px; margin-bottom:24px; }}
.title {{ font-size:24px; font-weight:bold; color:var(--accent); }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(240px,1fr)); gap:16px; margin-bottom:24px; }}
.card {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; }}
.score-box {{ text-align:center; }}
.score-val {{ font-size:48px; font-weight:900; color:{gauge_color}; }}
.score-grade {{ font-size:20px; color:var(--text-dim); }}
.badge {{ display:inline-block; padding:4px 8px; border-radius:6px; font-size:12px; font-weight:bold; }}
.badge-critical {{ background:#7f1d1d; color:#fca5a5; }}
.badge-high {{ background:#7c2d12; color:#fdba74; }}
.badge-medium {{ background:#78350f; color:#fde68a; }}
.badge-low {{ background:#064e3b; color:#6ee7b7; }}
.table-wrap {{ overflow-x:auto; background:var(--card); border:1px solid var(--border); border-radius:12px; padding:16px; }}
table {{ width:100%; border-collapse:collapse; text-align:right; }}
th, td {{ padding:12px 14px; border-bottom:1px solid var(--border); }}
th {{ color:var(--accent); font-size:14px; }}
tr:hover {{ background:#243248; }}
.code-box {{ background:#0b1120; border:1px solid var(--border); padding:8px 12px; border-radius:6px; font-family:monospace; direction:ltr; text-align:left; }}
input[type="text"] {{ width:100%; padding:10px 14px; background:#0b1120; border:1px solid var(--border); border-radius:8px; color:#fff; box-sizing:border-box; margin-bottom:16px; }}
</style>
</head>
<body>
<div class="header">
  <div>
    <div class="title">🛡️ تقرير AI AYFAM الأمني v5</div>
    <div style="color:var(--text-dim);margin-top:4px;">الجهاز: <b>{html.escape(hostname)}</b> | وقت الفحص: {now}</div>
  </div>
  <div style="text-align:left;">
    <span class="badge badge-critical">حرجة: {counts.get('critical',0)}</span>
    <span class="badge badge-high">عالية: {counts.get('high',0)}</span>
    <span class="badge badge-medium">متوسطة: {counts.get('medium',0)}</span>
  </div>
</div>

<div class="grid">
  <div class="card score-box">
    <div class="score-val">{score}/100</div>
    <div class="score-grade">التقدير الأمني: <b>{grade}</b></div>
    <div style="color:var(--text-dim);margin-top:8px;">{risk.get('label_ar','')}</div>
  </div>
  <div class="card">
    <h3 style="margin-top:0;color:var(--accent);">إحصائيات الفحص</h3>
    <p>إجمالي الملاحظات: <b>{len(findings)}</b></p>
    <p>تغطية تقنيات MITRE ATT&CK: <b>{len(set(sum([f.get('attack_ids',[]) for f in findings], [])))} تقنية</b></p>
  </div>
</div>

<div class="table-wrap">
  <h3 style="margin-top:0;color:var(--accent);">النتائج والتوصيات الأمنية</h3>
  <input type="text" id="search" placeholder="ابحث في النتائج، العناوين، أو التوصيات..." onkeyup="filterTable()">
  <table id="findingsTable">
    <thead>
      <tr>
        <th>المستوى</th>
        <th>الملاحظة</th>
        <th>التفاصيل</th>
        <th>تقنية الهجوم</th>
        <th>الحل المقترح</th>
      </tr>
    </thead>
    <tbody>
"""

    for f in findings:
        sev = f.get("severity", "info").lower()
        badge_cls = f"badge-{sev}" if sev in ("critical", "high", "medium", "low") else "badge-low"
        attack_str = ", ".join(f.get("attack_ids", [])) or "—"
        fix_str = f.get("fix", "")
        fix_html = f'<div class="code-box">{html.escape(fix_str)}</div>' if fix_str else "—"

        html_content += f"""      <tr>
        <td><span class="badge {badge_cls}">{sev.upper()}</span></td>
        <td><b>{html.escape(f.get('title',''))}</b></td>
        <td style="color:var(--text-dim);max-width:320px;">{html.escape(f.get('detail',''))}</td>
        <td><code>{html.escape(attack_str)}</code></td>
        <td>{fix_html}</td>
      </tr>
"""

    html_content += """    </tbody>
  </table>
</div>

<script>
function filterTable() {
  var input = document.getElementById("search");
  var filter = input.value.toLowerCase();
  var rows = document.getElementById("findingsTable").getElementsByTagName("tr");
  for (var i = 1; i < rows.length; i++) {
    var text = rows[i].textContent || rows[i].innerText;
    rows[i].style.display = text.toLowerCase().indexOf(filter) > -1 ? "" : "none";
  }
}
</script>
</body>
</html>
"""
    return html_content
