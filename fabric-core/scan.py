#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scan.py — Echter Netzwerk-Scan in die fabric-core Wissensbasis.

Laeuft nmap (Service-/Versionserkennung) in einem Docker-Container gegen ein
Ziel und meldet die offenen Dienste als Funde an fabric-core (/findings).
Danach zeigen AEGIS, OVERWATCH und ORAKEL deine ECHTEN Daten.

  WICHTIG: Nur Netze scannen, die DIR gehoeren oder fuer die du eine
  schriftliche Autorisierung hast. Scannen fremder Netze ist strafbar.

Nutzung:
  python scan.py 192.168.1.0/24                 # eigenes LAN
  python scan.py 192.168.1.50                    # einzelner Host
  python scan.py 192.168.1.0/24 http://localhost:8800
"""
import sys, subprocess, json, urllib.request
import xml.etree.ElementTree as ET

DEFAULT_FABRIC = "http://localhost:8800"

# Exponierte/heikle Dienste -> hoehere Einstufung
SENSITIVE = {21:"FTP",23:"Telnet",135:"MSRPC",139:"NetBIOS",445:"SMB",
             1433:"MSSQL",3306:"MySQL",3389:"RDP",5432:"PostgreSQL",
             5900:"VNC",6379:"Redis",9200:"Elasticsearch",27017:"MongoDB",
             11211:"Memcached",2375:"Docker-API"}

def run_nmap(target):
    print(f"[*] Starte nmap -sV gegen {target} (im Docker-Container) ...")
    try:
        out = subprocess.run(
            ["docker","run","--rm","instrumentisto/nmap","-sV","-T4","-oX","-",target],
            capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        print("[!] Docker nicht gefunden. Docker Desktop starten."); sys.exit(1)
    if out.returncode != 0 and not out.stdout.strip():
        print("[!] nmap-Fehler:", out.stderr[:400]); sys.exit(1)
    return out.stdout

def parse_and_post(xml_text, fabric):
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        print("[!] Konnte nmap-Ausgabe nicht lesen."); return 0
    n = 0
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        if addr_el is None:
            addr_el = host.find("address")
        ip = addr_el.get("addr") if addr_el is not None else "?"
        for port in host.findall(".//port"):
            st = port.find("state")
            if st is None or st.get("state") != "open":
                continue
            pid = int(port.get("portid"))
            svc = port.find("service")
            name = svc.get("name", "?") if svc is not None else "?"
            product = ""
            if svc is not None:
                product = (svc.get("product","") + " " + svc.get("version","")).strip()
            sev = "HOCH" if pid in SENSITIVE else "MITTEL"
            label = SENSITIVE.get(pid, name)
            finding = {
                "tool": "nmap",
                "target_ip": ip,
                "port": pid,
                "cve": "—",
                "title": f"{label} offen (Port {pid})",
                "severity": sev,
                "detail": f"Dienst: {name} {product}".strip(),
            }
            try:
                post(fabric, finding); n += 1
                print(f"    + {ip}:{pid}  {finding['title']}")
            except Exception as e:
                print(f"    ! Konnte Fund nicht melden ({ip}:{pid}): {e}")
    return n

def post(fabric, finding):
    req = urllib.request.Request(
        fabric.rstrip("/") + "/findings",
        data=json.dumps(finding).encode(),
        headers={"Content-Type": "application/json"})
    urllib.request.urlopen(req, timeout=15).read()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__); sys.exit(1)
    target = sys.argv[1]
    fabric = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_FABRIC
    print("="*60)
    print("  ACHTUNG: Nur EIGENE / autorisierte Netze scannen!")
    print(f"  Ziel: {target}   ->   fabric-core: {fabric}")
    print("="*60)
    xml_text = run_nmap(target)
    count = parse_and_post(xml_text, fabric)
    print("-"*60)
    if count:
        print(f"[+] {count} echte Funde an fabric-core gemeldet.")
        print("    ORAKEL/OVERWATCH/AEGIS zeigen sie jetzt. Frag ORAKEL z.B.:")
        print('    "Welche offenen Dienste sind in meinem Netz am riskantesten?"')
    else:
        print("[i] Keine offenen Ports gefunden (oder Ziel nicht erreichbar).")
