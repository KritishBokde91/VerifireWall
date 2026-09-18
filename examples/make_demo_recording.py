#!/usr/bin/env /usr/bin/python3
"""
VeriFireWall Demo — Screenshot-based Video Generator
======================================================
Uses Chrome DevTools Protocol (CDP) headless mode to capture
pixel-perfect screenshots, then stitches them into an MP4 with ffmpeg.
No display/GPU issues — guaranteed visible content.

Output: /home/Kritish/Development/verifierwall/verifirewall_demo.mp4
"""

import os, sys, subprocess, time, signal, json, threading, atexit, tempfile, base64
import urllib.request, urllib.parse, urllib.error, asyncio, websockets

# ─────────────────────────────────────────────────────────────────────────────
OUTPUT_VIDEO  = "/home/Kritish/Development/verifierwall/verifirewall_demo.mp4"
FRAMES_DIR    = "/tmp/vfw_frames"
CDP_PORT      = 9224
WIDTH, HEIGHT = 1920, 1080
FPS           = 12           # frames per second in output video
PROJ          = "/home/Kritish/Development/verifierwall"

DASHBOARD_URL  = "http://localhost:3002"
GRAFANA_URL    = "http://localhost:3001"
DOZZLE_URL     = "http://localhost:9999"
JUICESHOP_URL  = "http://localhost:3000"
PROM_URL       = "http://localhost:9090"

_pids = []

def cleanup():
    for p in _pids:
        try: os.kill(p, signal.SIGTERM)
        except: pass

atexit.register(cleanup)

# ─────────────────────────────────────────────────────────────────────────────
# Attacks
# ─────────────────────────────────────────────────────────────────────────────
ATTACKS = [
    ("/rest/user/login",  "email", "' OR '1'='1' --"),
    ("/products/search",  "q",     "1 UNION SELECT username,password FROM users--"),
    ("/comment",          "msg",   "<script>alert(document.cookie)</script>"),
    ("/profile",          "name",  "<img src=x onerror=alert(1)>"),
    ("/api/tools/ping",   "host",  "127.0.0.1; cat /etc/passwd"),
    ("/cgi-bin/test",     "cmd",   "() { :;}; echo $(whoami)"),
    ("/download",         "file",  "../../../../etc/passwd"),
    ("/view",             "doc",   "....//....//....//etc/shadow"),
]
BENIGN = ["/", "/products", "/about", "/contact", "/api/v1/status"]

def fire_attack(path, param, payload):
    import random
    enc = urllib.parse.urlencode({param: payload})
    req = urllib.request.Request(f"http://localhost:80{path}?{enc}",
                                  headers={"User-Agent": "VeriFireWall-Demo/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=3): pass
    except urllib.error.HTTPError as e:
        if e.code == 403:
            print(f"  [BLOCKED ✓] 403 — {path}")

def fire_benign():
    import random
    p = random.choice(BENIGN)
    try:
        urllib.request.urlopen(f"http://localhost:80{p}", timeout=3)
        print(f"  [ALLOWED]   BENIGN {p}")
    except: pass

def burst(count=20, ratio=0.65):
    import random
    for _ in range(count):
        if random.random() < ratio:
            fire_attack(*random.choice(ATTACKS))
        else:
            fire_benign()
        time.sleep(0.3)

# ─────────────────────────────────────────────────────────────────────────────
# Slides
# ─────────────────────────────────────────────────────────────────────────────
def write_slide(name, html):
    path = f"/tmp/vfw_{name}.html"
    with open(path, "w") as f: f.write(html)
    return f"file://{path}"

INTRO_HTML = write_slide("intro", """<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#0d0d1a 0%,#0a1628 50%,#0d0d1a 100%);display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:'Segoe UI',Arial,sans-serif;color:#e8eaf6;overflow:hidden}
.w{text-align:center;max-width:1000px;padding:40px}
.s{font-size:120px;display:block;margin-bottom:20px;animation:pulse 2s ease-in-out infinite}
@keyframes pulse{0%,100%{transform:scale(1)}50%{transform:scale(1.06)}}
h1{font-size:80px;font-weight:900;color:#00e5ff;text-shadow:0 0 40px rgba(0,229,255,0.5);margin-bottom:16px}
.tag{font-size:28px;color:#90caf9;letter-spacing:2px;margin-bottom:48px}
.bs{display:flex;gap:18px;justify-content:center;flex-wrap:wrap}
.b{padding:14px 28px;border-radius:50px;font-size:17px;font-weight:700}
.b1{background:rgba(0,229,255,.15);border:2px solid #00e5ff;color:#00e5ff}
.b2{background:rgba(170,0,255,.15);border:2px solid #aa00ff;color:#ce93d8}
.b3{background:rgba(255,23,68,.15);border:2px solid #ff1744;color:#ff5252}
.b4{background:rgba(76,175,80,.15);border:2px solid #4caf50;color:#81c784}
.sub{font-size:19px;color:#546e7a;margin-top:36px}
</style></head><body><div class="w">
<span class="s">🛡️</span>
<h1>VeriFireWall</h1>
<div class="tag">AI-Powered Web Application Firewall &amp; Network IDS</div>
<div class="bs">
<span class="b b1">⚡ ML-Based WAF</span>
<span class="b b2">🔬 Layer 4 NIDS</span>
<span class="b b3">🔥 Attack Detection</span>
<span class="b b4">📊 Real-time Analytics</span>
</div>
<div class="sub">open-appsec · NGINX · Docker · Prometheus · Grafana · UNSW-NB15 XGBoost</div>
</div></body></html>""")

ARCH_HTML = write_slide("arch", """<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d1117;font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;padding:60px;min-height:100vh}
h2{font-size:46px;font-weight:800;color:#00e5ff;margin-bottom:36px}
.g{display:grid;grid-template-columns:repeat(4,1fr);gap:18px;margin-bottom:32px}
.b{background:#161b22;border:2px solid #30363d;border-radius:14px;padding:24px;text-align:center}
.b.r{border-color:#ff1744}.b.g2{border-color:#4caf50}.b.b2{border-color:#00e5ff}.b.p{border-color:#aa00ff}
.ic{font-size:46px;margin-bottom:10px}
.lb{font-size:16px;font-weight:700;margin-bottom:6px}
.ds{font-size:13px;color:#8b949e;line-height:1.5}
.fl{display:flex;align-items:center;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:20px}
.fi{background:#161b22;border:2px solid #30363d;border-radius:8px;padding:10px 18px;font-size:15px;font-weight:600}
.fa{color:#4caf50;font-size:24px;font-weight:700}
</style></head><body>
<h2>🏗️ Architecture: How VeriFireWall Protects Your App</h2>
<div class="g">
<div class="b r"><div class="ic">👾</div><div class="lb">Attacker</div><div class="ds">SQL Injection · XSS · RCE<br>Path Traversal · Shellshock<br>DoS · Port Scan</div></div>
<div class="b b2"><div class="ic">🛡️</div><div class="lb">open-appsec Agent</div><div class="ds">ML Engine · Supervised +<br>Unsupervised Models<br>Layer 7 WAAP</div></div>
<div class="b g2"><div class="ic">🍹</div><div class="lb">OWASP JuiceShop</div><div class="ds">Intentionally Vulnerable<br>Node.js Backend<br>(port 3000)</div></div>
<div class="b p"><div class="ic">📊</div><div class="lb">Analytics Stack</div><div class="ds">Prometheus · Grafana<br>Dozzle · VeriFireWall<br>Dashboard (port 3002)</div></div>
</div>
<div class="fl">
<div class="fi" style="border-color:#ff1744;color:#ff5252">👾 Attack Request</div>
<div class="fa">→</div><div class="fi">🌐 NGINX + WAF</div>
<div class="fa">→</div><div class="fi">🛡️ ML Engine</div>
<div class="fa">→</div><div class="fi" style="border-color:#ff1744;color:#ff5252">🚫 403 BLOCKED</div>
</div>
<div class="fl" style="margin-top:14px">
<div class="fi" style="border-color:#4caf50;color:#81c784">✅ Benign Request</div>
<div class="fa">→</div><div class="fi">🌐 NGINX + WAF</div>
<div class="fa">→</div><div class="fi">🛡️ ML Engine</div>
<div class="fa">→</div><div class="fi" style="border-color:#4caf50;color:#81c784">🍹 200 OK</div>
</div>
</body></html>""")

ATTACK_SLIDE_HTML = write_slide("attack", """<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:#0d0d0d;font-family:'Courier New',Courier,monospace;color:#ff1744;padding:60px;min-height:100vh}
h2{font-size:50px;font-weight:900;color:#ff1744;margin-bottom:8px}
.sub{color:#ff5252;font-size:22px;margin-bottom:36px}
.g{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.a{background:#1a0000;border:2px solid #ff1744;border-radius:10px;padding:20px}
.at{font-size:20px;font-weight:700;color:#ff5252;margin-bottom:10px}
.ac{font-size:13px;color:#ffcdd2;background:#0d0000;padding:10px 14px;border-radius:6px;word-break:break-all;line-height:1.6}
.st{margin-top:40px;text-align:center;font-size:30px;color:#4caf50;font-weight:900;border:2px solid #4caf50;padding:20px;border-radius:10px;background:rgba(76,175,80,.08)}
</style></head><body>
<h2>🔥 Launching Attack Traffic NOW</h2>
<div class="sub">Real attack payloads fired at WAF-protected endpoint (http://localhost:80)</div>
<div class="g">
<div class="a"><div class="at">💉 SQL Injection</div><div class="ac">GET /rest/user/login?email=' OR '1'='1' --<br>GET /products/search?q=1 UNION SELECT username,password FROM users--</div></div>
<div class="a"><div class="at">🖼️ Cross-Site Scripting (XSS)</div><div class="ac">GET /comment?msg=&lt;script&gt;alert(document.cookie)&lt;/script&gt;<br>GET /profile?name=&lt;img src=x onerror=alert(1)&gt;</div></div>
<div class="a"><div class="at">💻 Command Injection</div><div class="ac">GET /api/tools/ping?host=127.0.0.1; cat /etc/passwd</div></div>
<div class="a"><div class="at">🐚 Shellshock RCE</div><div class="ac">GET /cgi-bin/test?cmd=() { :;}; echo $(whoami)</div></div>
<div class="a"><div class="at">📁 Path Traversal</div><div class="ac">GET /download?file=../../../../etc/passwd</div></div>
<div class="a"><div class="at">🗃️ Local File Inclusion</div><div class="ac">GET /view?doc=....//....//....//etc/shadow</div></div>
</div>
<div class="st">⚡ ALL ATTACKS FIRING — WAF BLOCKING IN REAL TIME → Watch the dashboard!</div>
</body></html>""")

RECAP_HTML = write_slide("recap", """<!DOCTYPE html><html><head><meta charset="UTF-8"><style>
*{margin:0;padding:0;box-sizing:border-box}
body{background:linear-gradient(135deg,#0d1117,#0a1628);font-family:'Segoe UI',Arial,sans-serif;color:#e6edf3;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:60px}
.w{max-width:960px;width:100%}
h2{font-size:54px;font-weight:900;color:#00e5ff;margin-bottom:40px;text-align:center;text-shadow:0 0 30px rgba(0,229,255,0.4)}
.g{display:grid;grid-template-columns:1fr 1fr;gap:22px}
.c{background:rgba(0,229,255,.06);border:2px solid rgba(0,229,255,.35);border-radius:14px;padding:26px}
.ci{font-size:38px;margin-bottom:12px}
.ct{font-size:20px;font-weight:700;color:#00e5ff;margin-bottom:8px}
.cd{font-size:15px;color:#8b949e;line-height:1.6}
.f{text-align:center;margin-top:48px;font-size:24px;color:#81c784;font-weight:700}
.us{display:flex;gap:14px;justify-content:center;margin-top:18px;flex-wrap:wrap}
.u{background:rgba(76,175,80,.1);border:2px solid #4caf50;border-radius:8px;padding:8px 18px;font-size:15px;color:#81c784;font-family:monospace}
</style></head><body><div class="w">
<h2>✅ VeriFireWall — Demo Complete</h2>
<div class="g">
<div class="c"><div class="ci">🛡️</div><div class="ct">ML-Powered WAF (Layer 7)</div><div class="cd">open-appsec blocks SQLi, XSS, RCE, Path Traversal, Shellshock in real-time with 403 responses. Zero false positives on benign traffic.</div></div>
<div class="c"><div class="ci">🔬</div><div class="ct">Layer 4 Network IDS</div><div class="cd">UNSW-NB15 XGBoost model (190 features) classifies live NetFlow for DoS, Port Scans, Exploits, and Fuzzers in ~1.8s per flow.</div></div>
<div class="c"><div class="ci">📊</div><div class="ct">Real-time Security Dashboard</div><div class="cd">Live attack counters, incident type breakdown (SQLi/XSS/RCE), anomaly confidence scores, threat levels, and event stream.</div></div>
<div class="c"><div class="ci">📈</div><div class="ct">Full Observability Stack</div><div class="cd">Prometheus scrapes NGINX metrics, Grafana visualizes attack trends, Dozzle streams live container logs — all fully containerized.</div></div>
</div>
<div class="f">🚀 Zero-Day Protection · No Cloud Required · Fully Open Source (Apache 2.0)</div>
<div class="us">
<span class="u">Dashboard :3002</span>
<span class="u">Grafana :3001</span>
<span class="u">Prometheus :9090</span>
<span class="u">Dozzle :9999</span>
<span class="u">JuiceShop :3000</span>
</div>
</div></body></html>""")

# ─────────────────────────────────────────────────────────────────────────────
# CDP (Headless Chrome via Remote Debugging Protocol)
# ─────────────────────────────────────────────────────────────────────────────
class CDP:
    def __init__(self, port):
        self.port = port
        self._ws = None
        self._ctr = 0
        self._results = {}
        self._loop = None
        self._ready = threading.Event()

    def _ws_url(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json") as r:
            return json.loads(r.read())[0]["webSocketDebuggerUrl"]

    async def _run(self):
        async with websockets.connect(self._ws_url(), max_size=2**25) as ws:
            self._ws = ws
            self._ready.set()
            try:
                while True:
                    d = json.loads(await ws.recv())
                    if "id" in d:
                        self._results[d["id"]] = d
            except: pass

    def start(self):
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, daemon=True).start()
        asyncio.run_coroutine_threadsafe(self._run(), self._loop)
        self._ready.wait(timeout=15)

    def send(self, method, params=None, wait=6):
        self._ctr += 1
        cid = self._ctr
        asyncio.run_coroutine_threadsafe(
            self._ws.send(json.dumps({"id": cid, "method": method, "params": params or {}})),
            self._loop
        )
        dl = time.time() + wait
        while time.time() < dl:
            if cid in self._results:
                return self._results.pop(cid)
            time.sleep(0.05)
        return {}

    def screenshot(self):
        """Return raw PNG bytes of current viewport."""
        r = self.send("Page.captureScreenshot", {
            "format": "png",
            "clip": {"x": 0, "y": 0, "width": WIDTH, "height": HEIGHT, "scale": 1},
            "captureBeyondViewport": False
        }, wait=10)
        data = r.get("result", {}).get("data", "")
        return base64.b64decode(data) if data else None

    def navigate(self, url):
        self.send("Page.navigate", {"url": url})
        time.sleep(0.5)
        # Wait for load event
        self.send("Page.enable")
        time.sleep(2)

    def js(self, code):
        return self.send("Runtime.evaluate", {"expression": code})

    def scroll(self, y):
        self.js(f"window.scrollBy({{top:{y},behavior:'auto'}})")
        time.sleep(0.3)

    def scroll_to(self, y=0):
        self.js(f"window.scrollTo(0,{y})")
        time.sleep(0.3)

    def set_size(self, w, h):
        self.send("Emulation.setDeviceMetricsOverride", {
            "width": w, "height": h,
            "deviceScaleFactor": 1,
            "mobile": False
        })

# ─────────────────────────────────────────────────────────────────────────────
# Frame capture loop
# ─────────────────────────────────────────────────────────────────────────────
frame_idx = [0]
stop_capture = threading.Event()

def capture_loop(cdp, interval=1.0/FPS):
    """Continuously capture screenshots and save as PNG frames."""
    while not stop_capture.is_set():
        t0 = time.time()
        try:
            png = cdp.screenshot()
            if png:
                path = f"{FRAMES_DIR}/frame_{frame_idx[0]:06d}.png"
                with open(path, "wb") as f:
                    f.write(png)
                frame_idx[0] += 1
        except Exception as e:
            pass
        elapsed = time.time() - t0
        wait = interval - elapsed
        if wait > 0:
            time.sleep(wait)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print("=" * 70)
    print("  🎬 VeriFireWall Demo — CDP Screenshot Recorder")
    print("=" * 70)

    # Prepare frames dir
    os.makedirs(FRAMES_DIR, exist_ok=True)
    for f in os.listdir(FRAMES_DIR):
        os.remove(f"{FRAMES_DIR}/{f}")
    print(f"✓ Frames dir ready: {FRAMES_DIR}")

    # Start headless Chrome
    chrome_profile = tempfile.mkdtemp()
    print(f"→ Launching headless Chrome (port {CDP_PORT})...")
    chrome = subprocess.Popen([
        "google-chrome-stable",
        "--headless=new",
        "--no-sandbox",
        "--disable-gpu",
        f"--remote-debugging-port={CDP_PORT}",
        f"--user-data-dir={chrome_profile}",
        f"--window-size={WIDTH},{HEIGHT}",
        "--force-device-scale-factor=1",
        "--disable-extensions",
        "--no-first-run",
        "--disable-background-networking",
        "about:blank"
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _pids.append(chrome.pid)

    # Wait for CDP
    for _ in range(30):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json", timeout=1)
            break
        except: time.sleep(0.5)
    else:
        print("✗ Chrome CDP timed out"); return 1
    print("✓ Chrome CDP ready")

    cdp = CDP(CDP_PORT)
    cdp.start()
    cdp.set_size(WIDTH, HEIGHT)
    print("✓ CDP connected, viewport set to 1920×1080\n")

    # Start frame capture thread
    cap_thread = threading.Thread(target=capture_loop, args=(cdp,), daemon=True)
    cap_thread.start()

    def hold(seconds, label=""):
        """Hold current view for N seconds (captures FPS*seconds frames)."""
        if label:
            print(f"  ⏱  Holding '{label}' for {seconds}s...")
        time.sleep(seconds)

    def show(url, settle=6, label=""):
        cdp.navigate(url)
        time.sleep(settle)

    # ── SCENE 1: INTRO (12s) ─────────────────────────────────────────────
    print("🎬 [1/12] Intro slide...")
    show(INTRO_HTML, settle=12, label="intro")

    # ── SCENE 2: ARCHITECTURE (12s) ──────────────────────────────────────
    print("🎬 [2/12] Architecture overview...")
    show(ARCH_HTML, settle=12, label="arch")

    # ── SCENE 3: JUICESHOP DIRECT (12s) ──────────────────────────────────
    print("🎬 [3/12] JuiceShop app (direct, no WAF)...")
    show(f"{JUICESHOP_URL}/#/", settle=8)
    cdp.scroll(400); time.sleep(3)
    cdp.scroll_to(0); time.sleep(2)

    # ── SCENE 4: DASHBOARD initial (12s) ─────────────────────────────────
    print("🎬 [4/12] VeriFireWall Dashboard — initial state...")
    show(DASHBOARD_URL, settle=8)
    cdp.scroll(500); time.sleep(3)
    cdp.scroll_to(0); time.sleep(2)

    # ── SCENE 5: ATTACK SLIDE (7s) ────────────────────────────────────────
    print("🎬 [5/12] Attack launch slide...")
    show(ATTACK_SLIDE_HTML, settle=7)

    # ── SCENE 6: DASHBOARD + live attacks (30s) ───────────────────────────
    print("🎬 [6/12] Dashboard + live attack burst #1...")
    show(DASHBOARD_URL, settle=5)
    print("  ⚔️  Firing burst #1 (20 requests)...")
    t1 = threading.Thread(target=burst, args=(20, 0.65), daemon=True)
    t1.start()
    time.sleep(6)
    cdp.scroll(500); time.sleep(6)
    cdp.scroll(500); time.sleep(5)
    t1.join(timeout=20)
    cdp.scroll_to(0); time.sleep(3)
    cdp.scroll(700); time.sleep(6)   # show event table
    cdp.scroll_to(0)

    # ── SCENE 7: GRAFANA (12s) ────────────────────────────────────────────
    print("🎬 [7/12] Grafana dashboard...")
    show(GRAFANA_URL, settle=6)
    cdp.js("""
    var u=document.querySelector('[placeholder="Email or username"]');
    var p=document.querySelector('[placeholder="Password"]');
    var b=document.querySelector('[type="submit"]');
    if(u&&p&&b){u.value='admin';p.value='appsec123';b.click();}
    """)
    time.sleep(5)
    cdp.scroll(400); time.sleep(4)
    cdp.scroll_to(0); time.sleep(2)

    # ── SCENE 8: PROMETHEUS (8s) ──────────────────────────────────────────
    print("🎬 [8/12] Prometheus metrics...")
    show(f"{PROM_URL}/graph", settle=8)

    # ── SCENE 9: DOZZLE logs (8s) ─────────────────────────────────────────
    print("🎬 [9/12] Dozzle container logs...")
    show(DOZZLE_URL, settle=5)
    cdp.js("""
    var ls=document.querySelectorAll('a');
    for(var l of ls){if(l.textContent&&l.textContent.toLowerCase().includes('appsec')){l.click();break;}}
    """)
    time.sleep(4)

    # ── SCENE 10: DASHBOARD + attack burst #2 (28s) ───────────────────────
    print("🎬 [10/12] Final attack burst on dashboard...")
    show(DASHBOARD_URL, settle=5)
    print("  ⚔️  Firing burst #2 (15 requests)...")
    t2 = threading.Thread(target=burst, args=(15, 0.7), daemon=True)
    t2.start()
    time.sleep(6); cdp.scroll(500); time.sleep(5)
    t2.join(timeout=15)
    cdp.scroll_to(0); time.sleep(3)
    cdp.scroll(600); time.sleep(5)
    cdp.scroll_to(0)

    # ── SCENE 11: LAYER 4 NIDS section (10s) ─────────────────────────────
    print("🎬 [11/12] Layer 4 NIDS ML section...")
    cdp.scroll(1500); time.sleep(8)
    cdp.scroll_to(0); time.sleep(2)

    # ── SCENE 12: RECAP (12s) ─────────────────────────────────────────────
    print("🎬 [12/12] Recap / outro slide...")
    show(RECAP_HTML, settle=12)

    # Stop capture
    stop_capture.set()
    cap_thread.join(timeout=3)
    chrome.terminate()

    total_frames = frame_idx[0]
    duration_est = total_frames / FPS
    print(f"\n✅ Captured {total_frames} frames (~{duration_est:.0f}s at {FPS}fps)")

    # ── ENCODE VIDEO ──────────────────────────────────────────────────────
    print(f"→ Encoding video → {OUTPUT_VIDEO}")
    ffmpeg_cmd = [
        "ffmpeg", "-y",
        "-framerate", str(FPS),
        "-i", f"{FRAMES_DIR}/frame_%06d.png",
        "-c:v", "libx264",
        "-preset", "medium",
        "-crf", "18",
        "-pix_fmt", "yuv420p",
        "-vf", "scale=1920:1080:flags=lanczos",
        "-movflags", "+faststart",
        OUTPUT_VIDEO
    ]
    result = subprocess.run(ffmpeg_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print("ffmpeg error:", result.stderr[-500:])
        return 1

    sz = os.path.getsize(OUTPUT_VIDEO)
    print(f"\n{'='*70}")
    print(f"  🎉 Recording complete!")
    print(f"  📹  {OUTPUT_VIDEO}")
    print(f"  📦  {sz/1_000_000:.1f} MB")
    print(f"  ⏱️   ~{duration_est:.0f} seconds ({total_frames} frames @ {FPS}fps)")
    print(f"{'='*70}")

    # Cleanup frames
    for f in os.listdir(FRAMES_DIR):
        os.remove(f"{FRAMES_DIR}/{f}")
    os.rmdir(FRAMES_DIR)
    return 0

if __name__ == "__main__":
    sys.exit(main())
