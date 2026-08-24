"""
FARIS security dashboard — full demo script support in the browser.

Run:  python dashboard.py
Open: http://127.0.0.1:8765

Supports: Demos 1-6 + vignette, tool decisions, provenance, trajectories,
human-review approve/reject, architecture strip, live ops snapshot.
"""

import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from pipeline import FARISPipeline
from demo_faris import run_demo_suite


PIPELINE = FARISPipeline()
DEMO_STATE = {"demos": [], "last_run": None}


def reset_pipeline() -> FARISPipeline:
    """Fresh controller so demos are clean (no leftover isolation)."""
    global PIPELINE
    PIPELINE = FARISPipeline()
    DEMO_STATE["demos"] = []
    DEMO_STATE["last_run"] = None
    return PIPELINE


def run_clean_suite():
    """Always start from a new pipeline, then run demos 1-6 + vignette."""
    faris = reset_pipeline()
    result = run_demo_suite(faris, quiet=True)
    DEMO_STATE["demos"] = result["demos"]
    DEMO_STATE["last_run"] = result["snapshot"]
    return result


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>FARIS Security Dashboard</title>
<style>
  :root { --bg:#0f1419; --card:#1a2332; --text:#e7ecf3; --muted:#8b9bb4;
          --accent:#3d9cf0; --bad:#e85d5d; --ok:#3ecf8e; --warn:#e6b84d; }
  * { box-sizing: border-box; }
  body { margin:0; font-family:"Segoe UI",system-ui,sans-serif; background:var(--bg); color:var(--text); }
  header { padding:1.1rem 1.4rem; border-bottom:1px solid #243044; }
  header h1 { margin:0; font-size:1.2rem; letter-spacing:.04em; }
  header p { margin:.3rem 0 0; color:var(--muted); font-size:.88rem; }
  .pipe { display:flex; flex-wrap:wrap; gap:.35rem; padding:.85rem 1.4rem; border-bottom:1px solid #243044; }
  .pipe span { background:#243044; color:var(--muted); font-size:.72rem; padding:.25rem .5rem; border-radius:4px; }
  .pipe span.on { color:#041018; background:var(--accent); font-weight:600; }
  .actions { padding:.9rem 1.4rem; display:flex; flex-wrap:wrap; gap:.5rem; align-items:center; }
  button { background:var(--accent); color:#041018; border:0; padding:.5rem .85rem; border-radius:6px; cursor:pointer; font-weight:600; }
  button.secondary { background:#243044; color:var(--text); }
  button.ok { background:var(--ok); }
  button.bad { background:var(--bad); color:#fff; }
  button:disabled { opacity:.5; cursor:not-allowed; }
  main { display:grid; grid-template-columns: 1.2fr 1fr; gap:1rem; padding:1rem 1.4rem 2rem; }
  @media (max-width: 980px) { main { grid-template-columns: 1fr; } }
  .card { background:var(--card); border:1px solid #243044; border-radius:8px; padding:1rem; }
  .card h2 { margin:0 0 .7rem; font-size:.9rem; color:var(--muted); text-transform:uppercase; letter-spacing:.06em; }
  .metric { font-size:2rem; font-weight:600; }
  .ok { color:var(--ok); } .bad { color:var(--bad); } .warn { color:var(--warn); }
  table { width:100%; border-collapse:collapse; font-size:.82rem; }
  th, td { text-align:left; padding:.35rem .3rem; border-bottom:1px solid #243044; vertical-align:top; }
  th { color:var(--muted); font-weight:500; }
  .bar { height:8px; background:#243044; border-radius:4px; overflow:hidden; margin-top:.45rem; }
  .bar > span { display:block; height:100%; background:var(--accent); }
  .demo { border:1px solid #243044; border-radius:8px; padding:.75rem; margin-bottom:.7rem; background:#121a26; }
  .demo.active { border-color:var(--accent); }
  .demo h3 { margin:0 0 .4rem; font-size:.95rem; }
  .tag { display:inline-block; font-size:.72rem; padding:.15rem .4rem; border-radius:4px; margin-right:.3rem; background:#243044; }
  .tag.allow { background:rgba(62,207,142,.2); color:var(--ok); }
  .tag.deny, .tag.block { background:rgba(232,93,93,.2); color:var(--bad); }
  .tag.review { background:rgba(230,184,77,.2); color:var(--warn); }
  pre.box { white-space:pre-wrap; word-break:break-word; background:#0c1118; border:1px solid #243044;
            border-radius:6px; padding:.6rem; font-size:.78rem; color:var(--muted); max-height:140px; overflow:auto; margin:.4rem 0; }
  .stack { display:flex; flex-direction:column; gap:1rem; }
    .tag.input { background:rgba(61,156,240,.2); color:var(--accent); }
    .input-block { margin-top:.55rem; padding:.55rem .65rem; background:#0c1118; border:1px solid #2a3a52; border-radius:6px; }
    .input-block .lbl { font-size:.72rem; color:var(--accent); text-transform:uppercase; letter-spacing:.05em; margin-bottom:.25rem; }
</style>
</head>
<body>
<header>
  <h1>FARIS — Financial AI Risk &amp; Integrity Shield</h1>
  <p>Pre-LLM / pre-tool controller for payment-workflow AI agents (synthetic demo data only).</p>
</header>
<div class="pipe" id="pipe"></div>
<div class="actions">
  <button onclick="runSuite()">Run full demo suite (1–6 + vignette)</button>
  <button class="secondary" onclick="resetDash()">Reset dashboard</button>
  <button class="secondary" onclick="refresh()">Refresh</button>
  <span class="status" id="status">Ready — click Run full demo suite. Left side should show DEMO 1–6 cards.</span>
</div>
<main>
  <div class="stack">
    <section class="card">
      <h2>Demo walkthrough (video script)</h2>
      <p class="muted">Authority: SYSTEM &gt; DEVELOPER &gt; USER &gt; EXTERNAL_UNTRUSTED · Prompts cannot self-grant capabilities · DATA ≠ INSTRUCTION</p>
      <div id="demos"><p class="muted">No demos yet. Run the suite.</p></div>
    </section>
  </div>
  <div class="stack">
    <section class="card">
      <h2>Overall AI Risk</h2>
      <div class="metric" id="riskMetric">—</div>
      <div class="bar"><span id="riskBar" style="width:0%"></span></div>
    </section>
    <section class="card">
      <h2>Active Agents</h2>
      <div id="agents"></div>
    </section>
    <section class="card">
      <h2>Human Review Queue</h2>
      <div id="reviews"></div>
    </section>
    <section class="card">
      <h2>Risk Trajectories</h2>
      <div id="traj"></div>
    </section>
    <section class="card">
      <h2>Tool Calls</h2>
      <div id="tools"></div>
    </section>
    <section class="card">
      <h2>Blocked / Denied</h2>
      <div id="blocked"></div>
    </section>
    <section class="card">
      <h2>Audit</h2>
      <pre class="box" id="audit"></pre>
    </section>
  </div>
</main>
<script>
function decClass(d){
  d = (d||'').toUpperCase();
  if(d==='ALLOW'||d==='ALLOW_DEGRADED') return 'allow';
  if(d==='REQUIRE_HUMAN_REVIEW'||d==='REQUIRE_CONFIRMATION') return 'review';
  return 'deny';
}
function esc(s){
  return String(s??'').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
function renderDemos(demos){
  const root = document.getElementById('demos');
  if(!demos || !demos.length){ root.innerHTML = '<p class="muted">No demos yet.</p>'; return; }
  root.innerHTML = demos.map(d => {
    const r = d.result || {};
    const dec = (r.decision||'').toUpperCase();
    let turns = '';
    if(d.turns && d.turns.length){
      turns = '<table><tr><th>Turn</th><th>Prompt</th><th>Risk</th><th>Decision</th><th>Trajectory</th></tr>' +
        d.turns.map(t => `<tr>
          <td>${t.turn}</td>
          <td>${esc(t.prompt)}</td>
          <td>${Number(t.risk_score).toFixed(2)}</td>
          <td><span class="tag ${decClass(t.decision)}">${esc(t.decision)}</span></td>
          <td>${esc((t.trajectory||[]).map(x=>Number(x).toFixed(2)).join(' → '))}</td>
        </tr>`).join('') + '</table>';
    }
    let tools = '';
    if(d.tools && d.tools.length){
      tools = d.tools.map(t => `<div class="muted">
        Tool <b>${esc(t.tool)}</b>
        <span class="tag ${decClass(t.decision)}">${esc(t.decision)}</span>
        executed=${esc(t.executed)}
        ${t.human_review_id?(' review='+esc(t.human_review_id)):''}
        <div>${esc(t.reason||'')}</div>
      </div>`).join('');
    }
    const preview = d.content_preview
      ? `<div class="input-block"><div class="lbl">${esc(d.external_input_type||'EXTERNAL INPUT')}</div><pre class="box" style="margin:0;border:0;background:transparent;padding:0">${esc(d.content_preview)}</pre></div>`
      : '';
    const notes = (d.notes||[]).map(n=>`<div class="muted">• ${esc(n)}</div>`).join('');
    const userInput = d.prompt
      ? `<div class="input-block"><div class="lbl">Input given</div><div>${esc(d.prompt)}</div></div>`
      : '';
    return `<article class="demo" id="${esc(d.id)}">
      <h3>${esc(d.title)}</h3>
      <div>
        <span class="tag ${decClass(dec)}">${esc(dec||'—')}</span>
        <span class="tag input">${esc(d.input_type||'INPUT')}</span>
        <span class="tag">risk ${r.risk_score!=null?Number(r.risk_score).toFixed(2):'—'}</span>
        <span class="tag">state ${esc(r.risk_state||'—')}</span>
        <span class="tag">provenance ${esc(d.provenance||'—')}</span>
        <span class="tag">cap_granted ${esc(r.capability_granted)}</span>
      </div>
      <div class="muted" style="margin-top:.4rem"><b>Input type:</b> ${esc(d.input_label||d.input_type||'—')}</div>
      ${userInput}
      ${preview}
      <div class="muted" style="margin-top:.45rem"><b>Attacks:</b> ${esc((r.attack_classes||[]).join(', ')||'none')}</div>
      <div class="muted"><b>Requested capability:</b> ${esc(r.requested_capability||'—')}</div>
      <div class="muted"><b>Reason:</b> ${esc(r.reason||'')}</div>
      ${r.human_review_id?`<div class="muted"><b>Human review id:</b> ${esc(r.human_review_id)}</div>`:''}
      ${turns}${tools}${notes}
    </article>`;
  }).join('');
}
function renderSnapshot(data){
  const risk = data.overall_ai_risk || 0;
  const rm = document.getElementById('riskMetric');
  rm.textContent = risk.toFixed(2);
  rm.className = 'metric ' + (risk>=0.7?'bad':risk>=0.4?'warn':'ok');
  document.getElementById('riskBar').style.width = Math.min(100, risk*100) + '%';

  document.getElementById('pipe').innerHTML =
    (data.architecture||[]).map((s,i)=>`<span class="on">${esc(s)}</span>${i<(data.architecture.length-1)?'<span>→</span>':''}`).join('');

  const agents = data.active_agents||[];
  document.getElementById('agents').innerHTML = `<table><tr><th>ID</th><th>Role</th><th>State</th><th>Score</th><th>Isolated</th></tr>
    ${agents.map(a=>`<tr><td>${esc(a.agent_id)}</td><td>${esc(a.role)}</td><td>${esc(a.risk_state)}</td>
    <td>${Number(a.risk_score).toFixed(2)}</td><td>${a.isolated}</td></tr>`).join('')||'<tr><td colspan=5>None</td></tr>'}</table>`;

  const queue = data.human_review_queue||[];
  document.getElementById('reviews').innerHTML = queue.length ? `<table><tr><th>ID</th><th>Agent</th><th>Reason</th><th>Action</th></tr>
    ${queue.map(q=>`<tr>
      <td>${esc(q.review_id)}</td><td>${esc(q.agent_id)}</td><td>${esc(q.reason)}</td>
      <td>
        <button class="ok" onclick="resolveReview('${esc(q.review_id)}','approve')">Approve</button>
        <button class="bad" onclick="resolveReview('${esc(q.review_id)}','reject')">Reject</button>
      </td>
    </tr>`).join('')}</table>` : '<p class="muted">Empty</p>';

  const sessions = data.sessions||{};
  let trajHtml = '<table><tr><th>Session</th><th>Risk</th><th>Trajectory</th></tr>';
  const entries = Object.entries(sessions);
  trajHtml += entries.length ? entries.map(([sid,info])=>{
    const series = (info.trajectory && info.trajectory.series) || [];
    return `<tr><td>${esc(sid)}</td><td>${Number(info.risk||0).toFixed(2)}</td>
      <td>${series.map(x=>Number(x).toFixed(2)).join(' → ')||'—'}</td></tr>`;
  }).join('') : '<tr><td colspan=3>None</td></tr>';
  trajHtml += '</table>';
  document.getElementById('traj').innerHTML = trajHtml;

  const tools = data.tool_calls||[];
  document.getElementById('tools').innerHTML = `<table><tr><th>Tool</th><th>Agent</th><th>Decision</th></tr>
    ${tools.slice().reverse().map(t=>`<tr><td>${esc(t.tool)}</td><td>${esc(t.agent_id)}</td>
    <td><span class="tag ${decClass(t.decision)}">${esc(t.decision)}</span></td></tr>`).join('')||'<tr><td colspan=3>None</td></tr>'}</table>`;

  const blocked = data.blocked_actions||[];
  document.getElementById('blocked').innerHTML = `<table><tr><th>Decision</th><th>Attacks</th><th>Reason</th><th>Provenance</th></tr>
    ${blocked.slice(-12).reverse().map(e=>`<tr>
      <td class="bad">${esc(e.decision)}</td>
      <td>${esc((e.attack_classes||[]).join(', '))}</td>
      <td>${esc(e.reason)}</td>
      <td>${esc(e.provenance||'')}</td>
    </tr>`).join('')||'<tr><td colspan=4>None</td></tr>'}</table>`;

  document.getElementById('audit').textContent =
    JSON.stringify(data.audit_summary||{},null,2) + '\n\n' +
    JSON.stringify((data.recent_events||[]).slice(-6),null,2);
}
async function refresh(){
  const res = await fetch('/api/snapshot');
  const data = await res.json();
  renderSnapshot(data);
  if(data.demos) renderDemos(data.demos);
}
async function runSuite(){
  document.getElementById('status').textContent = 'Resetting + running full demo suite...';
  const res = await fetch('/api/run_demo_suite', {method:'POST'});
  const data = await res.json();
  renderDemos(data.demos||[]);
  renderSnapshot(data.snapshot||{});
  const n = (data.demos||[]).length;
  document.getElementById('status').textContent =
    'Demo suite complete — '+n+' cards (expect 7: demos 1–6 + vignette). Scroll left panel.';
  const first = document.getElementById('demo-1');
  if(first) first.scrollIntoView({behavior:'smooth', block:'start'});
}
async function resetDash(){
  await fetch('/api/reset', {method:'POST'});
  renderDemos([]);
  await refresh();
  document.getElementById('status').textContent = 'Dashboard reset. Click Run full demo suite.';
}
async function resolveReview(id, action){
  const res = await fetch('/api/review?id='+encodeURIComponent(id)+'&action='+action, {method:'POST'});
  const data = await res.json();
  document.getElementById('status').textContent = action.toUpperCase()+' '+id+' → '+(data.status||data.error||'ok');
  await refresh();
}
refresh();
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print("[dashboard]", fmt % args)

    def _json(self, obj, code=200):
        payload = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if path == "/api/snapshot":
            snap = PIPELINE.dashboard_snapshot()
            snap["demos"] = DEMO_STATE["demos"]
            self._json(snap)
            return
        self.send_error(404)

    def do_POST(self):
        global PIPELINE
        parsed = urlparse(self.path)
        path = parsed.path
        if path in ("/api/run_demo_suite", "/api/run_demo"):
            # Always fresh pipeline — avoids isolation spam from prior clicks
            result = run_clean_suite()
            self._json(result)
            return
        if path == "/api/reset":
            reset_pipeline()
            self._json({"ok": True, "demos": [], "snapshot": PIPELINE.dashboard_snapshot()})
            return
        if path == "/api/review":
            qs = parse_qs(parsed.query)
            rid = (qs.get("id") or [""])[0]
            action = (qs.get("action") or [""])[0]
            if action == "approve":
                self._json(PIPELINE.human_review.approve(rid))
            elif action == "reject":
                self._json(PIPELINE.human_review.reject(rid))
            else:
                self._json({"error": "action must be approve|reject"}, 400)
            return
        self.send_error(404)


def main(host="127.0.0.1", port=8765):
    server = HTTPServer((host, port), Handler)
    print(f"FARIS dashboard at http://{host}:{port}")
    print("Click 'Run full demo suite' to execute Demos 1-6 + vignette in the UI.")
    server.serve_forever()


if __name__ == "__main__":
    main()
