# fabric-core — das Rückgrat der Aksoy-Net Security-Plattform

Eine **gemeinsame Wissensbasis** (SQLite) + **LLM-Gateway** + **RAG-Chat** in einem
kleinen FastAPI-Dienst. Alle Module (SENTINEL, AEGIS, PRISMA, ORAKEL) schreiben und
lesen hier — daraus entstehen echte **Korrelation**, **Feedback-Loop**, ein zentraler
**KI-Überwacher** und **RAG** aus EINER Quelle.

**Dynamisch by design:** Modelle wie bei Ollama wählbar & nachladbar, Gateway routet
lokal/remote, Updates sind Policy-gesteuert — und nach jedem Update läuft alles wieder lokal.

---

## Start

```bash
docker compose up -d
# Erstes Modell laden (lädt im Hintergrund, wie 'ollama pull'):
curl -X POST localhost:8800/models/pull -H 'Content-Type: application/json' -d '{"name":"qwen3:8b"}'
curl localhost:8800/health
```

Hinter deinen nginx-Proxy hängen (wie ki-archiv), z.B. `https://fabric.aksoy-net.de`.

---

## API (Auszug)

### Wissensbasis
| Methode | Pfad | Zweck |
|---|---|---|
| `POST` | `/events` | Alarm ablegen (SENTINEL) |
| `POST` | `/findings` | Schwachstelle ablegen (AEGIS) |
| `POST` | `/analyses` | KI-Analyse ablegen |
| `GET`  | `/correlate?ip=&port=` | Funde + Alarme zu einem Ziel → **escalate**-Flag |
| `POST` | `/overwatch` | Zentraler Lagebericht (KI-Überwacher) |

### RAG-Chat
```bash
curl -X POST localhost:8800/chat -H 'Content-Type: application/json' \
  -d '{"message":"Was ist mit 10.0.0.20 los?"}'
# -> {"answer": "...", "sources": [...], "backend": "local", "model": "qwen3:8b"}
```
RAG = Abruf aus der Wissensbasis (direkte IP-Treffer + SQLite-FTS5-Volltextsuche),
dann Antwort des gewählten Modells **gestützt auf das eigene Lagebild**.

### Modelle (dynamisch, wie Ollama)
| Methode | Pfad | Zweck |
|---|---|---|
| `GET`  | `/models` | installierte Modelle + kuratierter Katalog (nach VRAM-Stufe) |
| `POST` | `/models/pull` | Modell herunterladen `{"name":"gemma3:12b"}` |
| `POST` | `/models/activate` | aktives lokales Modell setzen |
| `DELETE` | `/models/{name}` | Modell entfernen |

### Updates / Upgrade (steuerbar)
| Methode | Pfad | Zweck |
|---|---|---|
| `GET`  | `/update/check` | Ist ein Update verfügbar? |
| `GET/PUT` | `/settings/update` | Policy: *was darf ein Update?* |
| `POST` | `/update/apply` | Update anwenden (Bestätigung nötig) |

**Policy-Defaults (sicher):** Modell-Updates erlaubt · Code-Updates aus ·
Bestätigung nötig · **nach Update → lokal**.

---

## Gateway-Routing (Souveränität)
- `sensitivity = "sensible"` → **lokal** (Ollama, Daten bleiben im Haus, DSGVO)
- `sensitivity = "heavy"` → **remote** (RunPod EU, nur schwere/unkritische Fälle)
- `sensitivity = "demo"` → Cloud (Demo-Brain)
- Default-Backend ist **lokal** und fällt nach Updates dorthin zurück.

## Skalierung
- Mehr Last → Ollama mit GPU (GTX 1070 später) in der compose freischalten.
- Schwere Modelle → RunPod-EU-Worker per `RUNPOD_URL`.
- Wissensbasis wächst → SQLite reicht lange; später Postgres + Vektor-Index möglich
  (RAG ist über `retrieve()` gekapselt, austauschbar).
