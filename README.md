# Aksoy-Net Security Platform

Ein modulares, **selbst gehostetes KI-Security-Fabric** — eine Kommandozentrale (NEXUS)
mit mehreren Modulen und einem gemeinsamen Gehirn (`fabric-core`). Lokal-first,
DSGVO-bewusst, mit optionalem schnellem Cloud-Backend.

> Fünf Fähigkeiten: **Verteidigen · Bewerten · Analysieren · Wissen · Überwachen.**

---

## Überblick

Kommerzielle, KI-gestützte SOC-Lösungen sind meist Cloud/SaaS und teuer. Diese Plattform
führt die Alarme vorhandener Security-Tools an **einer** Stelle zusammen, normalisiert und
korreliert sie und stellt ein **einheitliches Lagebild** bereit — schlank, self-hosted,
für Homelab, KMU und kleine Dienstleister.

## Module

| Modul | Rolle |
|---|---|
| **NEXUS** | Shell + Terminal, hostet alle Module |
| **ZENTRALE** | Kontrollzentrum — Modell, Benachrichtigung, Updates |
| **CONNECT** | Tools anbinden — Adressen, Live-Status, Selbsttest |
| **SENTINEL** | Verteidigen — Alarme, KI-Triage (LIVE/DEMO-Anzeige) |
| **AEGIS** | Bewerten — autorisierte Schwachstellen-Scans |
| **PRISMA** | Analysieren — Paket-Analyse & Korrelation |
| **ORAKEL** | Wissen — RAG-Chat auf Basis des eigenen Lagebilds |
| **OVERWATCH** | Überwachen — Fusion-Lagebild & Auto-Alarm |

**`fabric-core`** — das Rückgrat: FastAPI + SQLite (Wissensbasis) + LLM-Gateway (lokal
via Ollama **oder** Cloud) + RAG. Liefert die Oberfläche unter `/ui/` gleich mit aus.

## Architektur (kurz)

```
Quellen (CrowdSec/Wazuh/Grafana/Webhook)
        │  /ingest/...
        ▼
   fabric-core  ──►  LLM-Gateway (lokal Ollama | Cloud)
        │
        ├── Wissensbasis (SQLite): /events, /findings
        └── /ui/  ──►  NEXUS + Module
```

## Schnellstart

```bash
cd fabric-core
cp .env.example .env      # Werte eintragen (siehe unten)
docker compose up -d
curl localhost:8800/health
# Oberfläche: http://<SERVER>:8800/ui/NEXUS_Kommandozentrale.html
```

### Konfiguration (`fabric-core/.env`)
```
GROQ_KEY=...            # optionales schnelles Cloud-Backend (OpenAI-kompatibel)
GROQ_MODEL=...
DEFAULT_BACKEND=groq    # oder: local (Ollama)
```

## Tools anbinden

Jedes Tool schickt seine Alarme per Webhook an einen `/ingest`-Endpunkt:
`/ingest/crowdsec`, `/ingest/wazuh`, `/ingest/grafana`, `/ingest/webhook`.
Details: siehe [`fabric-core/CONNECTORS.md`](fabric-core/CONNECTORS.md).
Live-Status & Adressen findest du im Modul **CONNECT**.

## Netzwerk-Scan (nur eigene/autorisierte Netze!)

```bash
python fabric-core/scan.py 192.168.1.0/24
```

## Sicherheit

- **Keine Secrets im Repo:** `.env` ist per `.gitignore` ausgeschlossen — nur
  `.env.example` wird versioniert.
- Nur **eigene / autorisierte** Netze scannen.
- Zugriff möglichst hinter VPN (z. B. Tailscale) oder Zero-Trust-Proxy.

## Status

Aktives Entwicklungsprojekt (Homelab / Lernprojekt). Kein Anspruch auf
Produktivreife/Hochverfügbarkeit.

## Lizenz

Siehe [`LICENSE`](LICENSE).
