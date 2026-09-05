# Connectoren — echte Tools an fabric-core anschließen

Jedes Tool schickt seine Ereignisse per **Webhook** an `fabric-core`.
fabric-core normalisiert sie aufs gemeinsame Event-Schema. Kein Polling nötig.

> Basis-URL unten: `https://fabric.aksoy-net.de` (anpassen). Lokal: `http://fabric-core:8800`.

---

## CrowdSec → `/ingest/crowdsec`

CrowdSec hat ein HTTP-Notification-Plugin. Zwei Dateien:

**`/etc/crowdsec/notifications/http.yaml`**
```yaml
type: http
name: fabric_http
url: https://fabric.aksoy-net.de/ingest/crowdsec
method: POST
headers:
  Content-Type: application/json
# Template formt die Meldung in unser Schema:
format: |
  [{{range . -}}
    {"scenario":"{{.Scenario}}","ip":"{{.Source.Value}}","action":"{{.Remediation}}","message":"{{.Scenario}} von {{.Source.Value}}"}
  {{- end}}]
```

**`/etc/crowdsec/profiles.yaml`** — Notification aktivieren:
```yaml
notifications:
  - fabric_http
```
Dann: `sudo systemctl reload crowdsec`

---

## Wazuh → `/ingest/wazuh`

Wazuh-Integration als Skript. In **`/var/ossec/etc/ossec.conf`**:
```xml
<integration>
  <name>custom-fabric</name>
  <hook_url>https://fabric.aksoy-net.de/ingest/wazuh</hook_url>
  <level>7</level>            <!-- erst ab Level 7 melden -->
  <alert_format>json</alert_format>
</integration>
```
Minimales Skript **`/var/ossec/integrations/custom-fabric`** (ausführbar, chmod 750):
```bash
#!/bin/sh
# Wazuh übergibt die Alert-Datei als $1, die hook_url als $3
ALERT_FILE="$1"
URL="$3"
curl -s -X POST -H "Content-Type: application/json" --data "@${ALERT_FILE}" "$URL" >/dev/null 2>&1
```
Dann: `sudo systemctl restart wazuh-manager`

---

## Grafana → `/ingest/grafana`

Grafana **Alerting → Contact points → Webhook**:
- URL: `https://fabric.aksoy-net.de/ingest/grafana`
- Method: `POST`

Grafana sendet automatisch `{"alerts":[{labels, annotations, ...}]}` —
fabric-core liest `alertname`, `severity`, `instance`, `description`.

---

## Alles andere → `/ingest/webhook` (generisch)

Jedes Tool, das einen Webhook kann (Fail2ban, OPNsense, Uptime-Kuma, Skripte):
```bash
curl -X POST https://fabric.aksoy-net.de/ingest/webhook \
  -H 'Content-Type: application/json' \
  -d '{"source":"Fail2ban","severity":"HOCH","title":"SSH-Ban","ip":"203.0.113.7","detail":"3 Bans in 10 Min"}'
```

---

## Test (lokal)
```bash
curl -X POST localhost:8800/ingest/webhook \
  -d '{"source":"Test","severity":"KRITISCH","title":"Hallo Fabric","ip":"10.0.0.20"}'
curl localhost:8800/events           # sollte den Eintrag zeigen
```

Sobald Events fließen, korreliert PRISMA live, OVERWATCH fusioniert,
und ORAKEL beantwortet Fragen dazu — alles aus derselben Quelle.
