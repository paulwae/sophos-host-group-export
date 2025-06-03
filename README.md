# Sophos XG - Host Group Export Tool

Mit diesem Tool können FQDN- und IP-Host-Gruppen aus einer Sophos XG Firewall exportiert werden.

## Anwendung
```text
Voraussetzungen:
1:	Docker und Docker Compose
2:	amd64 oder arm64 (aarch64) Plattform


Export von FQDN- oder IP-Host-Gruppen aus der Firewall (in der Sophos XG Oberfläche):
1.1: SYSTEM → Backup & Firmware → Import export
1.2: „Export selective configuration“ auswählen
1.3: „FQDNHostGroup“ oder „IPHostGroup“ auswählen
1.4: Haken bei „Include dependent entity“ setzen
1.5: Exportieren und .tar-Datei speichern



Ordnerstruktur vorbereiten & Docker Compose Datei herunterladen:
2.1: Neuen Ordner anlegen
mkdir sophos-host-group-export

2.2: Im neu erstellten Ordner folgenden Curl Befehl für Download der docker-compose.yml ausführen:
cd sophos-host-group-export

Unix: curl -O https://raw.githubusercontent.com/paulwae/sophos-host-group-export/main/docker-compose.yml

PowerShell:  Invoke-WebRequest -Uri "https://raw.githubusercontent.com/paulwae/sophos-host-group-export/main/docker-compose.yml" -OutFile "docker-compose.yml"

2.3: API-Backup im Ordner ablegen (es wird immer automatisch das Backup mit dem jüngsten Änderungsdatum verwendet):
Beispiel:
sophos-host-group-export/
├── docker-compose.yml
└── API-*.tar



Tool ausführen:
3.1: Docker Image herunterladen:
docker compose pull

3.2: Container starte:
docker compose run --rm group-export


Das Tool durchsucht den Ordner nach dem neuesten Backup und exportiert die enthaltenen FQDN- oder IP-Host-Gruppen.
