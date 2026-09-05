#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fabric-core — das Rückgrat der Aksoy-Net Security-Plattform.

Eine gemeinsame Wissensbasis (SQLite) + LLM-Gateway + RAG-Chat in einem
kleinen FastAPI-Dienst. Alle Module (SENTINEL, AEGIS, PRISMA, ORAKEL)
schreiben und lesen hier -> echte Korrelation, Feedback-Loop, zentraler
KI-Ueberwacher und RAG aus EINER Quelle.

Dynamisch by design:
  - Modelle wie bei Ollama waehlbar & nachladbar (pull/list/delete)
  - Gateway routet pro Anfrage: lokal (Ollama) | remote (RunPod EU) | demo
  - Update/Upgrade steuerbar (Policy: was darf ein Update?) -> nach Update lokal
"""
import os, re, json, sqlite3, time, subprocess, threading, smtplib, urllib.request, urllib.error
from email.mime.text import MIMEText
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

# ── Konfiguration (alles per ENV ueberschreibbar) ───────────────────────────
DB_PATH        = os.getenv("FABRIC_DB", "/data/fabric.db")
OLLAMA_URL     = os.getenv("OLLAMA_URL", "http://ollama:11434")
RUNPOD_URL     = os.getenv("RUNPOD_URL", "")          # OpenAI-kompatibel, EU-Region
RUNPOD_KEY     = os.getenv("RUNPOD_KEY", "")
ANTHROPIC_KEY  = os.getenv("ANTHROPIC_KEY", "")       # nur fuer Demo-Brain/Cloud
GROQ_URL       = os.getenv("GROQ_URL", "https://api.groq.com/openai/v1/chat/completions")
GROQ_KEY       = os.getenv("GROQ_KEY", "")            # schnelle Cloud-Inferenz (OpenAI-kompatibel)
GROQ_MODEL     = os.getenv("GROQ_MODEL", "qwen/qwen3-32b")  # exakt wie in der Lern-App setzen
DEFAULT_BACKEND= os.getenv("DEFAULT_BACKEND", "local")  # nach Update -> lokal
VERSION        = os.getenv("FABRIC_VERSION", "0.1.0")
UPDATE_MANIFEST= os.getenv("UPDATE_MANIFEST_URL", "")  # JSON mit {"version": "..."}

# Kuratierter Modell-Katalog (nach VRAM-Stufe) — fuer die "wie bei Ollama"-Auswahl
MODEL_REGISTRY = [
    {"name": "qwen3:8b",        "tier": "8GB",  "use": "Standard lokal, schnell"},
    {"name": "gemma3:12b",      "tier": "8GB",  "use": "Gut fuer Erklaerungen"},
    {"name": "phi4",            "tier": "8GB",  "use": "Kompakt, stark im Reasoning"},
    {"name": "qwen3:32b",       "tier": "24GB", "use": "Tiefe Analysen"},
    {"name": "gemma3:27b",      "tier": "24GB", "use": "Breites Wissen"},
    {"name": "deepseek-r1:70b", "tier": "40GB+","use": "Schwere Faelle (remote/RunPod)"},
]

# ── Datenbank ───────────────────────────────────────────────────────────────
@contextmanager
def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()

def init_db():
    with db() as con:
        c = con.cursor()
        c.executescript("""
        CREATE TABLE IF NOT EXISTS assets(
            id INTEGER PRIMARY KEY, ip TEXT UNIQUE, hostname TEXT, notes TEXT, ts TEXT);
        CREATE TABLE IF NOT EXISTS events(
            id INTEGER PRIMARY KEY, source TEXT, severity TEXT, title TEXT,
            detail TEXT, ip TEXT, raw TEXT, ts TEXT);
        CREATE TABLE IF NOT EXISTS findings(
            id INTEGER PRIMARY KEY, tool TEXT, target_ip TEXT, port INTEGER,
            cve TEXT, title TEXT, severity TEXT, detail TEXT, ts TEXT);
        CREATE TABLE IF NOT EXISTS analyses(
            id INTEGER PRIMARY KEY, ref_type TEXT, ref_id INTEGER, model TEXT,
            content TEXT, ts TEXT);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
        -- Volltext-Index fuer RAG (SQLite FTS5)
        CREATE VIRTUAL TABLE IF NOT EXISTS kb_fts USING fts5(
            kind, ref_id UNINDEXED, ip, title, body, ts UNINDEXED);
        """)
        # Default Update-Policy
        defaults = {
            "update.auto_check": "true",
            "update.allow_model_updates": "true",
            "update.allow_code_updates": "false",
            "update.require_confirm": "true",
            "update.revert_to_local": "true",
            "gateway.default_backend": DEFAULT_BACKEND,
            "gateway.local_model": "qwen3:8b",
            # Benachrichtigung (Versand des Lageberichts)
            "notify.channel": "none",           # none | telegram | email | webhook
            "notify.telegram_token": "",
            "notify.telegram_chat": "",
            "notify.smtp_host": "", "notify.smtp_port": "587",
            "notify.smtp_user": "", "notify.smtp_pass": "",
            "notify.smtp_from": "", "notify.smtp_to": "",
            "notify.webhook_url": "",
            # Auto-Ueberwachung
            "overwatch.auto": "false",
            "overwatch.interval_min": "30",
        }
        for k, v in defaults.items():
            c.execute("INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v))

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")

def get_setting(key, default=None):
    with db() as con:
        r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return r["value"] if r else default

def set_setting(key, value):
    with db() as con:
        con.execute("INSERT INTO settings(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))

def fts_add(kind, ref_id, ip, title, body, ts):
    with db() as con:
        con.execute("INSERT INTO kb_fts(kind,ref_id,ip,title,body,ts) VALUES(?,?,?,?,?,?)",
                    (kind, ref_id, ip or "", title or "", body or "", ts))

# ── HTTP-Helfer (ohne Extra-Abhaengigkeiten) ────────────────────────────────
def http_json(url, payload=None, headers=None, timeout=600, method=None):
    data = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method or ("POST" if data else "GET"))
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())

# ── LLM-Gateway ─────────────────────────────────────────────────────────────
class Gateway:
    """Routet pro Anfrage zum richtigen Backend.
       sensitivity='sensible' -> lokal | 'heavy' -> remote | 'demo' -> cloud."""

    def pick_backend(self, requested: Optional[str], sensitivity: Optional[str]):
        if requested in ("local", "remote", "demo", "groq"):
            return requested
        if sensitivity == "sensible":
            return "local"                      # sensible Daten bleiben immer lokal
        if sensitivity == "heavy" and RUNPOD_URL:
            return "remote"
        if sensitivity == "demo":
            return "demo"
        return get_setting("gateway.default_backend", DEFAULT_BACKEND)

    def chat(self, messages, model=None, backend=None, sensitivity=None):
        backend = self.pick_backend(backend, sensitivity)
        if backend == "local":
            return self._ollama(messages, model or get_setting("gateway.local_model", "qwen3:8b"))
        if backend == "groq":
            return self._groq(messages, model or GROQ_MODEL)
        if backend == "remote":
            return self._openai(RUNPOD_URL, RUNPOD_KEY, messages, model or "local")
        if backend == "demo":
            return self._anthropic(messages, model or "claude-sonnet-4-6")
        raise HTTPException(400, f"Unbekanntes Backend: {backend}")

    def _groq(self, messages, model):
        if not GROQ_KEY:
            raise HTTPException(400, "GROQ_KEY nicht gesetzt (in docker-compose.yml eintragen).")
        r = http_json(GROQ_URL, {"model": model, "messages": messages, "stream": False},
                      {"Authorization": f"Bearer {GROQ_KEY}"})
        return {"content": r["choices"][0]["message"]["content"], "backend": "groq", "model": model}

    def _ollama(self, messages, model):
        try:
            r = http_json(f"{OLLAMA_URL}/api/chat",
                          {"model": model, "messages": messages, "stream": False})
            return {"content": r.get("message", {}).get("content", ""), "backend": "local", "model": model}
        except urllib.error.URLError as e:
            raise HTTPException(503, f"Ollama nicht erreichbar ({e}). Modell geladen? (POST /models/pull)")

    def _openai(self, base, key, messages, model):
        if not base: raise HTTPException(400, "RUNPOD_URL nicht gesetzt")
        hdr = {"Authorization": f"Bearer {key}"} if key else {}
        r = http_json(base, {"model": model, "messages": messages, "stream": False}, hdr)
        return {"content": r["choices"][0]["message"]["content"], "backend": "remote", "model": model}

    def _anthropic(self, messages, model):
        if not ANTHROPIC_KEY: raise HTTPException(400, "ANTHROPIC_KEY nicht gesetzt (Demo)")
        sys = "".join(m["content"] for m in messages if m["role"] == "system")
        usr = [m for m in messages if m["role"] != "system"]
        r = http_json("https://api.anthropic.com/v1/messages",
                      {"model": model, "max_tokens": 1024, "system": sys, "messages": usr},
                      {"x-api-key": ANTHROPIC_KEY, "anthropic-version": "2023-06-01"})
        return {"content": "".join(b.get("text", "") for b in r.get("content", [])),
                "backend": "demo", "model": model}

gw = Gateway()

# ── RAG: Abruf aus der Wissensbasis ─────────────────────────────────────────
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

def retrieve(query: str, limit: int = 8):
    """Holt relevanten Kontext: direkte IP-Treffer + Volltextsuche (FTS5)."""
    hits, seen = [], set()
    with db() as con:
        # 1) Harte IP-Treffer (starkes Signal)
        for ip in set(IP_RE.findall(query)):
            for row in con.execute(
                "SELECT 'event' k,id,ip,title,detail body,ts FROM events WHERE ip=? "
                "UNION ALL SELECT 'finding',id,target_ip,title,detail,ts FROM findings WHERE target_ip=? "
                "ORDER BY ts DESC", (ip, ip)):
                key = (row["k"], row["id"])
                if key not in seen:
                    seen.add(key); hits.append(dict(row))
        # 2) Volltextsuche
        terms = " OR ".join(re.findall(r"[a-zA-Z0-9_.\-]{3,}", query)) or query
        try:
            for row in con.execute(
                "SELECT kind k, ref_id id, ip, title, body, ts FROM kb_fts "
                "WHERE kb_fts MATCH ? ORDER BY rank LIMIT ?", (terms, limit)):
                key = (row["k"], row["id"])
                if key not in seen:
                    seen.add(key); hits.append(dict(row))
        except sqlite3.OperationalError:
            pass
    return hits[:limit]

def build_context(hits):
    if not hits:
        return "(Keine passenden Eintraege im Lagebild gefunden.)"
    lines = []
    for h in hits:
        lines.append(f"[{h['k'].upper()} #{h['id']} | {h.get('ip','')} | {h['ts']}] "
                     f"{h['title']}: {h.get('body','')}")
    return "\n".join(lines)

# ── FastAPI ─────────────────────────────────────────────────────────────────
app = FastAPI(title="fabric-core", version=VERSION)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Frontend (NEXUS + Module) mitausliefern, wenn der Ordner gemountet ist -> /ui/
WEB_DIR = os.getenv("WEB_DIR", "/web")
if os.path.isdir(WEB_DIR):
    app.mount("/ui", StaticFiles(directory=WEB_DIR, html=True), name="ui")

@app.on_event("startup")
def _startup():
    init_db()
    t = threading.Thread(target=_watcher, daemon=True)
    t.start()

@app.get("/health")
def health(): return {"ok": True, "version": VERSION, "backend": get_setting("gateway.default_backend")}

# ---- Wissensbasis: Events (SENTINEL) ----
class EventIn(BaseModel):
    source: str; severity: str; title: str
    detail: str = ""; ip: str = ""; raw: str = ""

@app.post("/events")
def add_event(e: EventIn):
    ts = now()
    with db() as con:
        cur = con.execute("INSERT INTO events(source,severity,title,detail,ip,raw,ts) "
                          "VALUES(?,?,?,?,?,?,?)",
                          (e.source, e.severity, e.title, e.detail, e.ip, e.raw, ts))
        eid = cur.lastrowid
        if e.ip:
            con.execute("INSERT OR IGNORE INTO assets(ip,hostname,notes,ts) VALUES(?,?,?,?)",
                        (e.ip, "", "", ts))
    fts_add("event", eid, e.ip, e.title, e.detail, ts)
    return {"id": eid, "ts": ts}

@app.get("/events")
def list_events(limit: int = 50):
    with db() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM events ORDER BY ts DESC LIMIT ?", (limit,))]

# ---- Wissensbasis: Findings (AEGIS) ----
class FindingIn(BaseModel):
    tool: str; target_ip: str; title: str; severity: str
    port: int = 0; cve: str = "—"; detail: str = ""

@app.post("/findings")
def add_finding(f: FindingIn):
    ts = now()
    with db() as con:
        cur = con.execute("INSERT INTO findings(tool,target_ip,port,cve,title,severity,detail,ts) "
                          "VALUES(?,?,?,?,?,?,?,?)",
                          (f.tool, f.target_ip, f.port, f.cve, f.title, f.severity, f.detail, ts))
        fid = cur.lastrowid
        con.execute("INSERT OR IGNORE INTO assets(ip,hostname,notes,ts) VALUES(?,?,?,?)",
                    (f.target_ip, "", "", ts))
    fts_add("finding", fid, f.target_ip,
            f"{f.title} ({f.cve})", f"{f.detail} Port {f.port}", ts)
    return {"id": fid, "ts": ts}

@app.get("/findings")
def list_findings(limit: int = 50):
    with db() as con:
        return [dict(r) for r in con.execute(
            "SELECT * FROM findings ORDER BY ts DESC LIMIT ?", (limit,))]

# ---- Korrelation (der Feedback-Loop-Kern) ----
@app.get("/correlate")
def correlate(ip: str, port: int = 0):
    """Liefert Schwachstellen + Alarme zu einem Ziel. Stuft Schweregrad hoch,
       wenn ein verwundbares Ziel zugleich angegriffen wird."""
    with db() as con:
        finds = [dict(r) for r in con.execute(
            "SELECT * FROM findings WHERE target_ip=?"
            + (" AND (port=? OR port=0)" if port else ""),
            (ip, port) if port else (ip,))]
        evts = [dict(r) for r in con.execute(
            "SELECT * FROM events WHERE ip=? ORDER BY ts DESC LIMIT 20", (ip,))]
    has_crit = any((f.get("severity", "").upper() in ("KRITISCH", "CRITICAL", "C")) for f in finds)
    under_attack = len(evts) > 0
    escalate = has_crit and under_attack
    return {"ip": ip, "port": port, "findings": finds, "events": evts,
            "escalate": escalate,
            "rationale": ("Verwundbares Ziel wird aktiv angegriffen -> Schweregrad hochstufen."
                          if escalate else "Keine kombinierte Hochstufung noetig.")}

# ---- KI-Analysen ablegen ----
class AnalysisIn(BaseModel):
    ref_type: str; ref_id: int; model: str; content: str

@app.post("/analyses")
def add_analysis(a: AnalysisIn):
    ts = now()
    with db() as con:
        cur = con.execute("INSERT INTO analyses(ref_type,ref_id,model,content,ts) "
                          "VALUES(?,?,?,?,?)", (a.ref_type, a.ref_id, a.model, a.content, ts))
        aid = cur.lastrowid
    fts_add("analyse", aid, "", f"KI-Analyse {a.ref_type}#{a.ref_id}", a.content, ts)
    return {"id": aid, "ts": ts}

# ---- RAG-Chat ----
class ChatIn(BaseModel):
    message: str
    model: Optional[str] = None
    backend: Optional[str] = None      # local | remote | demo
    sensitivity: Optional[str] = None  # sensible | heavy | demo

@app.post("/chat")
def chat(c: ChatIn):
    hits = retrieve(c.message)
    context = build_context(hits)
    system = ("Du bist die KI der Aksoy-Net Security-Plattform. Antworte praezise auf Deutsch, "
              "ausschliesslich gestuetzt auf das folgende LAGEBILD. Steht etwas nicht drin, sag das offen. "
              "Nenne relevante IDs.\n\n=== LAGEBILD ===\n" + context)
    out = gw.chat([{"role": "system", "content": system},
                   {"role": "user", "content": c.message}],
                  model=c.model, backend=c.backend, sensitivity=c.sensitivity)
    return {"answer": out["content"], "backend": out["backend"], "model": out["model"],
            "sources": [{"kind": h["k"], "id": h["id"], "title": h["title"]} for h in hits]}

# ---- Zentraler KI-Ueberwacher ----
def _overwatch_report():
    with db() as con:
        evts = [dict(r) for r in con.execute(
            "SELECT severity,title,ip,ts FROM events ORDER BY ts DESC LIMIT 30")]
        finds = [dict(r) for r in con.execute(
            "SELECT severity,title,target_ip,cve,ts FROM findings ORDER BY ts DESC LIMIT 30")]
    ev_ips = {e["ip"] for e in evts if e["ip"] and e["ip"] != "-"}
    fi_ips = {f["target_ip"] for f in finds if f["target_ip"]}
    both = sorted(ev_ips & fi_ips)
    crit = [ip for ip in both if
            any(e["ip"] == ip and (e["severity"] or "").upper() == "KRITISCH" for e in evts)
            or any(f["target_ip"] == ip and (f["severity"] or "").upper() == "KRITISCH" for f in finds)]
    summary = (f"Alarme: {json.dumps(evts, ensure_ascii=False)}\n"
               f"Schwachstellen: {json.dumps(finds, ensure_ascii=False)}\n"
               f"Korrelierte Ziele (Alarm+Luecke): {json.dumps(both)}")
    out = gw.chat([
        {"role": "system", "content": "Du bist der zentrale Security-Ueberwacher. Erstelle einen "
         "knappen deutschen Lagebericht: kritischste Punkte, Korrelationen (gleiche IP in Alarm "
         "und Schwachstelle = hoechste Prioritaet), klare Handlungsempfehlung."},
        {"role": "user", "content": summary}])
    return {"report": out["content"], "backend": out["backend"], "events": len(evts),
            "findings": len(finds), "correlated_targets": both, "critical_targets": crit}

@app.post("/overwatch")
def overwatch(notify: bool = False):
    r = _overwatch_report()
    if notify:
        r["notified"] = send_notify("🛰️ OVERWATCH-Lagebericht\n\n" + r["report"])
    return r

# ── Dynamisches Modell-Management (wie bei Ollama) ───────────────────────────
@app.get("/models")
def models():
    installed = []
    try:
        r = http_json(f"{OLLAMA_URL}/api/tags", timeout=10)
        installed = [m["name"] for m in r.get("models", [])]
    except Exception:
        pass
    return {"installed": installed, "registry": MODEL_REGISTRY,
            "active": get_setting("gateway.local_model"),
            "default_backend": get_setting("gateway.default_backend")}

class PullIn(BaseModel):
    name: str

@app.post("/models/pull")
def models_pull(p: PullIn):
    """Laedt ein Modell ueber Ollama herunter (kann dauern)."""
    if get_setting("update.allow_model_updates", "true") != "true":
        raise HTTPException(403, "Modell-Updates per Policy deaktiviert.")
    try:
        r = http_json(f"{OLLAMA_URL}/api/pull", {"name": p.name, "stream": False}, timeout=1800)
        return {"name": p.name, "status": r.get("status", "ok")}
    except urllib.error.URLError as e:
        raise HTTPException(503, f"Ollama nicht erreichbar: {e}")

@app.delete("/models/{name}")
def models_delete(name: str):
    try:
        http_json(f"{OLLAMA_URL}/api/delete", {"name": name}, method="DELETE", timeout=30)
        return {"deleted": name}
    except urllib.error.URLError as e:
        raise HTTPException(503, f"Ollama nicht erreichbar: {e}")

class ActivateIn(BaseModel):
    model: str

@app.post("/models/activate")
def models_activate(a: ActivateIn):
    set_setting("gateway.local_model", a.model)
    return {"active": a.model}

# ── Update / Upgrade-Steuerung ──────────────────────────────────────────────
@app.get("/settings/update")
def get_update_policy():
    keys = ["auto_check", "allow_model_updates", "allow_code_updates",
            "require_confirm", "revert_to_local"]
    return {k: get_setting(f"update.{k}") for k in keys} | \
           {"default_backend": get_setting("gateway.default_backend"), "version": VERSION}

class PolicyIn(BaseModel):
    auto_check: Optional[bool] = None
    allow_model_updates: Optional[bool] = None
    allow_code_updates: Optional[bool] = None
    require_confirm: Optional[bool] = None
    revert_to_local: Optional[bool] = None

@app.put("/settings/update")
def set_update_policy(p: PolicyIn):
    for k, v in p.dict().items():
        if v is not None:
            set_setting(f"update.{k}", "true" if v else "false")
    return get_update_policy()

@app.get("/update/check")
def update_check():
    latest = VERSION
    if UPDATE_MANIFEST:
        try:
            latest = http_json(UPDATE_MANIFEST, timeout=10).get("version", VERSION)
        except Exception:
            pass
    return {"current": VERSION, "latest": latest, "update_available": latest != VERSION}

class ApplyIn(BaseModel):
    confirm: bool = False
    scope: str = "models"   # "models" | "code"

@app.post("/update/apply")
def update_apply(a: ApplyIn):
    if get_setting("update.require_confirm", "true") == "true" and not a.confirm:
        raise HTTPException(400, "Bestaetigung erforderlich (confirm=true).")
    result = {"scope": a.scope}
    if a.scope == "models":
        # vorhandene Modelle aktualisieren (latest tag neu ziehen)
        if get_setting("update.allow_model_updates", "true") != "true":
            raise HTTPException(403, "Modell-Updates per Policy deaktiviert.")
        result["note"] = "Modelle via /models/pull aktualisierbar."
    elif a.scope == "code":
        if get_setting("update.allow_code_updates", "false") != "true":
            raise HTTPException(403, "Code-Updates per Policy deaktiviert (sicher voreingestellt).")
        try:
            out = subprocess.run(["git", "pull", "--ff-only"], cwd=os.path.dirname(__file__) or ".",
                                  capture_output=True, text=True, timeout=120)
            result["git"] = (out.stdout + out.stderr).strip()
            result["restart_required"] = True
        except Exception as e:
            raise HTTPException(500, f"Code-Update fehlgeschlagen: {e}")
    # Sicherheits-Default: nach jedem Update zurueck auf lokal
    if get_setting("update.revert_to_local", "true") == "true":
        set_setting("gateway.default_backend", "local")
        result["backend_after_update"] = "local"
    return result

# ── Connectoren: Ereignisse von echten Tools entgegennehmen ─────────────────
# Jedes Tool sendet per Webhook an /ingest/<tool>. Wir normalisieren -> events.

@app.post("/ingest/webhook")
async def ingest_webhook(request: Request):
    """Generisch: {source,severity,title,detail,ip}."""
    p = await request.json()
    return add_event(EventIn(source=p.get("source", "Webhook"),
        severity=str(p.get("severity", "HOCH")).upper(), title=p.get("title", "Ereignis"),
        detail=p.get("detail", ""), ip=p.get("ip", ""), raw=json.dumps(p)[:2000]))

@app.post("/ingest/crowdsec")
async def ingest_crowdsec(request: Request):
    """CrowdSec http-Notification (Liste oder Einzel)."""
    p = await request.json()
    items = p if isinstance(p, list) else [p]
    n = 0
    for a in items:
        if not isinstance(a, dict):
            continue
        ip = a.get("ip") or (a.get("source") or {}).get("value") or ""
        scen = a.get("scenario") or a.get("title") or a.get("message") or "CrowdSec-Alarm"
        action = str(a.get("action", "")).lower()
        sev = "KRITISCH" if "ban" in action else "HOCH"
        add_event(EventIn(source="CrowdSec", severity=sev, title=scen,
                  detail=a.get("message", scen), ip=ip, raw=json.dumps(a)[:2000])); n += 1
    return {"ingested": n}

@app.post("/ingest/wazuh")
async def ingest_wazuh(request: Request):
    """Wazuh integration (Alert-JSON)."""
    p = await request.json()
    rule = p.get("rule", {}) or {}
    data = p.get("data", {}) or {}
    agent = p.get("agent", {}) or {}
    lvl = int(rule.get("level", 0) or 0)
    sev = "KRITISCH" if lvl >= 12 else "HOCH" if lvl >= 7 else "MITTEL" if lvl >= 4 else "INFO"
    ip = data.get("srcip") or agent.get("ip") or ""
    return add_event(EventIn(source="Wazuh", severity=sev,
        title=rule.get("description", "Wazuh-Regel"),
        detail=p.get("full_log", rule.get("description", "")), ip=ip, raw=json.dumps(p)[:2000]))

@app.post("/ingest/grafana")
async def ingest_grafana(request: Request):
    """Grafana Webhook Contact Point."""
    p = await request.json()
    alerts = p.get("alerts", []) or [p]
    n = 0
    for al in alerts:
        lab = al.get("labels", {}) or {}
        ann = al.get("annotations", {}) or {}
        sev = str(lab.get("severity", "WARNUNG")).upper()
        title = lab.get("alertname") or ann.get("summary") or "Grafana-Alarm"
        add_event(EventIn(source="Grafana", severity=sev, title=title,
                  detail=ann.get("description", ""), ip=lab.get("instance", ""),
                  raw=json.dumps(al)[:2000])); n += 1
    return {"ingested": n}

# ── Benachrichtigung: Lagebericht versenden ─────────────────────────────────
def send_telegram(text):
    tok = get_setting("notify.telegram_token"); chat = get_setting("notify.telegram_chat")
    if not tok or not chat:
        return False
    http_json(f"https://api.telegram.org/bot{tok}/sendMessage",
              {"chat_id": chat, "text": text[:4000]}, timeout=20)
    return True

def send_email(text):
    host = get_setting("notify.smtp_host")
    if not host:
        return False
    port = int(get_setting("notify.smtp_port", "587") or 587)
    user = get_setting("notify.smtp_user"); pw = get_setting("notify.smtp_pass")
    frm = get_setting("notify.smtp_from") or user; to = get_setting("notify.smtp_to")
    if not to:
        return False
    msg = MIMEText(text, _charset="utf-8")
    msg["Subject"] = "OVERWATCH Lagebericht"; msg["From"] = frm; msg["To"] = to
    with smtplib.SMTP(host, port, timeout=20) as s:
        try: s.starttls()
        except Exception: pass
        if user: s.login(user, pw)
        s.sendmail(frm, [x.strip() for x in to.split(",")], msg.as_string())
    return True

def send_webhook(text):
    url = get_setting("notify.webhook_url")
    if not url:
        return False
    http_json(url, {"text": text}, timeout=20)
    return True

def send_notify(text):
    ch = get_setting("notify.channel", "none")
    try:
        if ch == "telegram": return send_telegram(text)
        if ch == "email":    return send_email(text)
        if ch == "webhook":  return send_webhook(text)
    except Exception:
        return False
    return False

class NotifyIn(BaseModel):
    text: str

@app.post("/notify")
def notify_ep(n: NotifyIn):
    if not send_notify(n.text):
        raise HTTPException(400, "Kein Kanal konfiguriert oder Versand fehlgeschlagen.")
    return {"sent": True, "channel": get_setting("notify.channel")}

@app.get("/settings/notify")
def get_notify_cfg():
    pub = ["channel", "telegram_chat", "smtp_host", "smtp_port", "smtp_user",
           "smtp_from", "smtp_to", "webhook_url"]   # ohne Geheimnisse
    out = {k: get_setting("notify." + k, "") for k in pub}
    out["overwatch_auto"] = get_setting("overwatch.auto")
    out["overwatch_interval_min"] = get_setting("overwatch.interval_min")
    return out

class NotifyCfg(BaseModel):
    channel: Optional[str] = None
    telegram_token: Optional[str] = None
    telegram_chat: Optional[str] = None
    smtp_host: Optional[str] = None; smtp_port: Optional[str] = None
    smtp_user: Optional[str] = None; smtp_pass: Optional[str] = None
    smtp_from: Optional[str] = None; smtp_to: Optional[str] = None
    webhook_url: Optional[str] = None
    overwatch_auto: Optional[bool] = None
    overwatch_interval_min: Optional[int] = None

@app.put("/settings/notify")
def set_notify_cfg(c: NotifyCfg):
    for k, v in c.dict().items():
        if v is None:
            continue
        if k == "overwatch_auto":
            set_setting("overwatch.auto", "true" if v else "false")
        elif k == "overwatch_interval_min":
            set_setting("overwatch.interval_min", str(v))
        else:
            set_setting("notify." + k, str(v))
    return get_notify_cfg()

# ── Auto-Wächter: periodisch Lagebericht, bei kritischer Korrelation melden ──
def _watcher():
    time.sleep(20)  # nach Start kurz warten
    while True:
        try:
            if get_setting("overwatch.auto", "false") == "true":
                r = _overwatch_report()
                if r.get("critical_targets"):
                    send_notify("🛰️ AUTO-LAGEBERICHT — kritische Korrelation!\n"
                                f"Ziele: {', '.join(r['critical_targets'])}\n\n" + r["report"])
        except Exception:
            pass
        try:
            mins = int(get_setting("overwatch.interval_min", "30") or 30)
        except ValueError:
            mins = 30
        time.sleep(max(60, mins * 60))
