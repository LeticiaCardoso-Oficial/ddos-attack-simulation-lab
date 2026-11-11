"""
DDoS Attack Simulation Lab - Red Team vs Blue Team
USO EXCLUSIVAMENTE EDUCACIONAL. Tudo roda em 127.0.0.1.

- Target Server  : endpoints /api/ping e /api/work (capacidade finita de workers)
- Red Team       : gerador de carga com limites rígidos e botão STOP
- Blue Team      : dashboard + defesas (rate limiting e load shedding)
"""
import collections, statistics, threading, time

import psutil
import requests
from flask import Flask, g, jsonify, render_template_string, request

# ---------------------------------------------------------------- config
HOST, PORT = "127.0.0.1", 5000
BASE = f"http://{HOST}:{PORT}"          # alvo FIXO: o simulador nunca aceita outro destino
LIMITS = {"max_concurrency": 50, "max_duration": 30, "max_requests": 5000}

WORKERS = threading.BoundedSemaphore(4)  # "capacidade" do servidor: 4 workers
WORK_TIME = 0.10                         # 100 ms de processamento por requisição
QUEUE_TIMEOUT = 2.0                      # espera máxima por um worker -> 503
RL_RATE, RL_BURST = 15, 15               # token bucket: 15 req/s por cliente
MAX_INFLIGHT = 8                         # load shedding acima de 8 requisições simultâneas

DEFENSES = {"rate_limit": False, "load_shed": False}
TRACKED = ("/api/ping", "/api/work")

app = Flask(__name__)
lock = threading.Lock()
EVENTS = collections.deque(maxlen=50000)   # (ts, latência, status, bloqueada_por_defesa)
HISTORY = collections.deque(maxlen=120)    # 1 ponto por segundo
STATE = {"total": 0, "inflight": 0, "peak_cpu": 0.0}
BUCKETS = {}
RESULTS = {}

# ---------------------------------------------------------------- target server
def allowed(cid):
    now = time.time()
    with lock:
        b = BUCKETS.setdefault(cid, [RL_BURST, now])
        b[0] = min(RL_BURST, b[0] + (now - b[1]) * RL_RATE)
        b[1] = now
        if b[0] >= 1:
            b[0] -= 1
            return True
    return False


@app.before_request
def guard():
    g.t0, g.blocked = time.time(), False
    if request.path != "/api/work":
        return None
    cid = request.headers.get("X-Client-Id", request.remote_addr)
    if DEFENSES["rate_limit"] and not allowed(cid):
        g.blocked = True
        r = jsonify(error="rate limit exceeded"); r.status_code = 429
        return r
    if DEFENSES["load_shed"] and STATE["inflight"] >= MAX_INFLIGHT:
        g.blocked = True
        r = jsonify(error="server busy"); r.status_code = 503
        return r
    return None


@app.after_request
def record(resp):
    if request.path in TRACKED:
        with lock:
            STATE["total"] += 1
            EVENTS.append((time.time(), time.time() - g.t0, resp.status_code, g.blocked))
        if g.blocked:
            resp.headers["X-Defense"] = "blocked"
    return resp


@app.route("/api/ping")
def ping():
    return jsonify(ok=True)


@app.route("/api/work")
def work():
    with lock:
        STATE["inflight"] += 1
    try:
        if not WORKERS.acquire(timeout=QUEUE_TIMEOUT):
            return jsonify(error="timeout waiting for worker"), 503
        try:
            time.sleep(WORK_TIME)          # simula processamento
        finally:
            WORKERS.release()
        return jsonify(ok=True)
    finally:
        with lock:
            STATE["inflight"] -= 1


# ---------------------------------------------------------------- monitoramento
def sampler():
    psutil.cpu_percent(None)
    while True:
        time.sleep(1)
        now = time.time()
        with lock:
            ev = [e for e in EVENTS if now - e[0] <= 1]
        served = [e for e in ev if not e[3]]
        n = len(ev)
        lat = statistics.mean(e[1] for e in served) * 1000 if served else 0
        err = 100 * sum(1 for e in served if e[2] >= 500) / len(served) if served else 0
        cpu = psutil.cpu_percent(None)
        STATE["peak_cpu"] = max(STATE["peak_cpu"], cpu)
        status = "CRÍTICO" if (err > 30 or lat > 1500) else "DEGRADADO" if (err > 5 or lat > 400) else "SAUDÁVEL"
        HISTORY.append(dict(t=time.strftime("%H:%M:%S"), rps=n, blocked=n - len(served), lat=round(lat, 1),
                            err=round(err, 1), cpu=cpu, mem=psutil.virtual_memory().percent, status=status))


# ---------------------------------------------------------------- Red Team (simulador)
class Sim:
    stop = threading.Event()
    running = False
    label = ""
    sent = 0


def run_load(conc, dur, maxreq, with_probe=True):
    """Carga sintética contra BASE (localhost). Limites rígidos aplicados aqui."""
    conc = max(1, min(int(conc), LIMITS["max_concurrency"]))
    dur = max(1, min(float(dur), LIMITS["max_duration"]))
    maxreq = max(1, min(int(maxreq), LIMITS["max_requests"]))
    Sim.stop.clear(); Sim.running = True; Sim.sent = 0
    attack, probe, t0 = [], [], time.time()
    end = t0 + dur

    def call(session, cid, bucket):
        t = time.time()
        try:
            r = session.get(BASE + "/api/work", headers={"X-Client-Id": cid}, timeout=3)
            code, blocked = r.status_code, r.headers.get("X-Defense") == "blocked"
        except requests.RequestException:
            code, blocked = 0, False
        bucket.append((time.time() - t, code, blocked))

    def attacker():
        s = requests.Session()
        while not Sim.stop.is_set() and time.time() < end:
            with lock:
                if Sim.sent >= maxreq:
                    return
                Sim.sent += 1
            call(s, "attacker", attack)

    def legit_user():                       # usuário legítimo: mede o impacto real
        s = requests.Session()
        while not Sim.stop.is_set() and time.time() < end:
            call(s, "legit", probe)
            time.sleep(0.25)

    threads = [threading.Thread(target=attacker, daemon=True) for _ in range(conc)]
    if with_probe:
        threads.append(threading.Thread(target=legit_user, daemon=True))
    for t in threads: t.start()
    for t in threads: t.join()
    Sim.running = False
    return attack, probe, max(time.time() - t0, 0.1)


def summarize(attack, probe, elapsed):
    def pct(v, p):
        v = sorted(v); return v[min(len(v) - 1, int(len(v) * p))] if v else 0
    lp = [x[0] * 1000 for x in probe]
    n = max(1, len(attack))
    return dict(
        attack_rps=round(len(attack) / elapsed, 1),
        blocked_pct=round(100 * sum(1 for x in attack if x[2]) / n, 1),
        server_err_pct=round(100 * sum(1 for x in attack if (x[1] >= 500 or x[1] == 0) and not x[2]) / n, 1),
        legit_avg_ms=round(statistics.mean(lp), 1) if lp else 0,
        legit_p95_ms=round(pct(lp, .95), 1),
        legit_ok_pct=round(100 * sum(1 for x in probe if x[1] == 200) / max(1, len(probe)), 1),
        peak_cpu=STATE["peak_cpu"])


SCENARIOS = {
    "baseline":   dict(conc=2,  dur=8,  rl=False, shed=False),
    "high_load":  dict(conc=40, dur=10, rl=False, shed=False),
    "mitigation": dict(conc=40, dur=10, rl=True,  shed=True),
}


def run_scenarios(names):
    for name in names:
        if Sim.stop.is_set(): break
        c = SCENARIOS[name]
        Sim.label = name
        DEFENSES.update(rate_limit=c["rl"], load_shed=c["shed"])
        STATE["peak_cpu"] = 0.0; BUCKETS.clear()
        a, p, el = run_load(c["conc"], c["dur"], LIMITS["max_requests"])
        if not Sim.stop.is_set():
            RESULTS[name] = summarize(a, p, el)
        time.sleep(2)                        # intervalo para o servidor se recuperar
    Sim.label = ""


# ---------------------------------------------------------------- API
@app.route("/api/metrics")
def metrics():
    return jsonify(history=list(HISTORY), total=STATE["total"], defenses=DEFENSES, results=RESULTS,
                   running=Sim.running, label=Sim.label, sent=Sim.sent, limits=LIMITS)


@app.route("/api/defense", methods=["POST"])
def defense():
    for k, v in (request.get_json() or {}).items():
        if k in DEFENSES: DEFENSES[k] = bool(v)
    return jsonify(DEFENSES)


@app.route("/api/sim/start", methods=["POST"])
def sim_start():
    if Sim.running: return jsonify(error="simulação em andamento"), 409
    d = request.get_json() or {}
    Sim.label = "custom"
    threading.Thread(target=lambda: run_load(d.get("conc", 10), d.get("dur", 10), LIMITS["max_requests"]), daemon=True).start()
    return jsonify(ok=True)


@app.route("/api/sim/stop", methods=["POST"])
def sim_stop():
    Sim.stop.set()
    return jsonify(ok=True)


@app.route("/api/scenario/<name>", methods=["POST"])
def scenario(name):
    if Sim.running: return jsonify(error="simulação em andamento"), 409
    names = list(SCENARIOS) if name == "all" else [name]
    if any(n not in SCENARIOS for n in names): return jsonify(error="cenário inválido"), 404
    Sim.stop.clear()
    threading.Thread(target=run_scenarios, args=(names,), daemon=True).start()
    return jsonify(ok=True)


# ---------------------------------------------------------------- Blue Team dashboard
PAGE = """<!doctype html><html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>DDoS Lab - Blue Team</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{--bg:#0e1a24;--panel:#142533;--line:#24415a;--tx:#dbe8f2;--mut:#7f9bb3;--ok:#3ddc97;--warn:#f5b942;--bad:#ff5d6c;--blue:#4aa8ff}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.5 "IBM Plex Sans","Segoe UI",system-ui,sans-serif}
header{padding:20px 28px;border-bottom:1px solid var(--line);display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:12px}
h1{font-size:20px;margin:0}small{color:var(--mut)}
main{padding:20px 28px;display:grid;gap:16px;max-width:1300px;margin:auto}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.k{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:12px 14px}
.k b{display:block;font-size:26px;font-variant-numeric:tabular-nums}.k span{color:var(--mut);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(380px,1fr));gap:16px}
.p{background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:14px}
.p h2{font-size:15px;margin:0 0 10px}
.ctl{display:flex;flex-wrap:wrap;gap:14px;align-items:center}
button{background:#1d3a52;color:var(--tx);border:1px solid var(--line);padding:8px 14px;border-radius:5px;cursor:pointer;font:inherit}
button:hover{background:#264b69}button:focus-visible{outline:2px solid var(--blue)}
button.stop{background:var(--bad);color:#fff;border:0;font-weight:700}
label{color:var(--mut);display:inline-flex;gap:6px;align-items:center}
#state{padding:6px 14px;border-radius:5px;font-weight:700;background:var(--ok);color:#06210f}
table{width:100%;border-collapse:collapse;font-variant-numeric:tabular-nums}
td,th{padding:6px 8px;border-bottom:1px solid var(--line);text-align:right}td:first-child,th:first-child{text-align:left}
canvas{max-height:230px}
</style></head><body>
<header><div><h1>DDoS Simulation Lab: Red Team vs Blue Team</h1>
<small>Ambiente local (127.0.0.1) com fins educacionais</small></div>
<div>Estado do servidor: <span id="state">SAUDÁVEL</span></div></header>
<main>
<section class="kpis">
<div class="k"><b id="rps">0</b><span>Requisições/s</span></div>
<div class="k"><b id="total">0</b><span>Total recebido</span></div>
<div class="k"><b id="lat">0</b><span>Tempo médio (ms)</span></div>
<div class="k"><b id="err">0%</b><span>Erros HTTP 5xx</span></div>
<div class="k"><b id="blk">0</b><span>Bloqueadas pela defesa/s</span></div>
<div class="k"><b id="cpu">0%</b><span>CPU</span></div>
<div class="k"><b id="mem">0%</b><span>Memória</span></div></section>

<section class="p"><h2>Red Team: carga sintética controlada</h2><div class="ctl">
<label>Concorrência <input id="conc" type="range" min="1" max="50" value="20"><output id="cv">20</output></label>
<label>Duração (s) <input id="dur" type="range" min="1" max="30" value="10"><output id="dv">10</output></label>
<button id="start">Iniciar simulação</button><button class="stop" id="stop">PARAR AGORA</button>
<small id="simstat"></small></div>
<small>Limites rígidos: 50 conexões, 30 s, 5000 requisições. O alvo é fixo em 127.0.0.1.</small></section>

<section class="p"><h2>Blue Team: defesas</h2><div class="ctl">
<label><input type="checkbox" id="rl"> Rate limiting (15 req/s por cliente)</label>
<label><input type="checkbox" id="shed"> Limite de concorrência (load shedding)</label></div></section>

<section class="p"><h2>Cenários</h2><div class="ctl">
<button data-s="baseline">1. Baseline</button><button data-s="high_load">2. High Load</button>
<button data-s="mitigation">3. Mitigation</button><button data-s="all">Executar os 3</button></div>
<table style="margin-top:12px"><thead><tr><th>Cenário</th><th>Req/s atacante</th><th>Bloqueadas</th><th>Erros 5xx</th>
<th>Usuário legítimo: média</th><th>p95</th><th>Sucesso</th><th>CPU pico</th></tr></thead><tbody id="res"></tbody></table></section>

<section class="grid">
<div class="p"><h2>Requisições por segundo</h2><canvas id="c1"></canvas></div>
<div class="p"><h2>Tempo de resposta médio (ms)</h2><canvas id="c2"></canvas></div>
<div class="p"><h2>CPU e memória (%)</h2><canvas id="c3"></canvas></div>
<div class="p"><h2>Latência do usuário legítimo por cenário (ms)</h2><canvas id="c4"></canvas></div></section>
</main>
<script>
const $=i=>document.getElementById(i);
const colors={SAUDÁVEL:'#3ddc97',DEGRADADO:'#f5b942',CRÍTICO:'#ff5d6c'};
Chart.defaults.color='#7f9bb3';Chart.defaults.borderColor='#24415a';
function mk(id,type,sets){return new Chart($(id),{type,data:{labels:[],datasets:sets.map(([l,c])=>({label:l,data:[],borderColor:c,backgroundColor:c,pointRadius:0,tension:.3}))},options:{animation:false,responsive:true}})}
const c1=mk('c1','line',[['Total','#4aa8ff'],['Bloqueadas','#f5b942']]);
const c2=mk('c2','line',[['Latência','#ff5d6c']]);
const c3=mk('c3','line',[['CPU','#4aa8ff'],['RAM','#3ddc97']]);
const c4=mk('c4','bar',[['Média','#4aa8ff'],['p95','#f5b942']]);
function fill(c,labels,...series){c.data.labels=labels;series.forEach((s,i)=>c.data.datasets[i].data=s);c.update()}
const post=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
async function tick(){
 const m=await (await fetch('/api/metrics')).json(),h=m.history,l=h[h.length-1]||{};
 $('rps').textContent=l.rps??0;$('total').textContent=m.total;$('lat').textContent=l.lat??0;
 $('err').textContent=(l.err??0)+'%';$('blk').textContent=l.blocked??0;$('cpu').textContent=(l.cpu??0)+'%';$('mem').textContent=(l.mem??0)+'%';
 $('state').textContent=l.status||'SAUDÁVEL';$('state').style.background=colors[l.status]||colors['SAUDÁVEL'];
 $('rl').checked=m.defenses.rate_limit;$('shed').checked=m.defenses.load_shed;
 $('simstat').textContent=m.running?`Em execução (${m.label}): ${m.sent} requisições enviadas`:'Parado';
 const t=h.map(x=>x.t);
 fill(c1,t,h.map(x=>x.rps),h.map(x=>x.blocked));fill(c2,t,h.map(x=>x.lat));fill(c3,t,h.map(x=>x.cpu),h.map(x=>x.mem));
 const names=['baseline','high_load','mitigation'].filter(n=>m.results[n]);
 fill(c4,names,names.map(n=>m.results[n].legit_avg_ms),names.map(n=>m.results[n].legit_p95_ms));
 $('res').innerHTML=names.map(n=>{const r=m.results[n];return `<tr><td>${n}</td><td>${r.attack_rps}</td><td>${r.blocked_pct}%</td><td>${r.server_err_pct}%</td><td>${r.legit_avg_ms} ms</td><td>${r.legit_p95_ms} ms</td><td>${r.legit_ok_pct}%</td><td>${r.peak_cpu}%</td></tr>`}).join('');
}
$('conc').oninput=e=>$('cv').textContent=e.target.value;$('dur').oninput=e=>$('dv').textContent=e.target.value;
$('start').onclick=()=>post('/api/sim/start',{conc:+$('conc').value,dur:+$('dur').value});
$('stop').onclick=()=>post('/api/sim/stop');
$('rl').onchange=e=>post('/api/defense',{rate_limit:e.target.checked});
$('shed').onchange=e=>post('/api/defense',{load_shed:e.target.checked});
document.querySelectorAll('[data-s]').forEach(b=>b.onclick=()=>post('/api/scenario/'+b.dataset.s));
setInterval(tick,1000);tick();
</script></body></html>"""


@app.route("/")
def index():
    return render_template_string(PAGE)


if __name__ == "__main__":
    threading.Thread(target=sampler, daemon=True).start()
    print(f"Dashboard: {BASE}  (apenas localhost)")
    app.run(host=HOST, port=PORT, threaded=True)
