# Homelab - HackMyVM (Medium)
 
![Homelab.png](Homelab.png)

## Übersicht

*   **VM:** Homelab
*   **Plattform:** [https://hackmyvm.eu/machines/machine.php?vm=homelab](https://hackmyvm.eu/machines/machine.php?vm=homelab)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 2025-05-14
*   **Original-Writeup:** [https://alientec1908.github.io/homelab_HackMyVM_Medium/](https://alientec1908.github.io/homelab_HackMyVM_Medium/)
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Zugriff auf die virtuelle Maschine "Homelab" zu erlangen. Der Lösungsweg umfasste die initiale Aufklärung eines Webservers, der sich als ein veralteter Mac OS X Server herausstellte. Durch IP-Spoofing mittels des `X-Forwarded-For`-Headers konnte auf eine interne OpenVPN-Konfigurationsseite zugegriffen werden. Die dort gefundenen Zertifikate und ein verschlüsselter privater Schlüssel wurden heruntergeladen. Die Passphrase des privaten Schlüssels wurde mittels eines Brute-Force-Skripts geknackt. Mit den entschlüsselten Zugangsdaten wurde eine VPN-Verbindung hergestellt, die Zugriff auf ein internes Netzwerksegment gewährte. In diesem Segment wurde ein weiterer Host identifiziert, auf den via SSH mit den zuvor für den VPN-Key gefundenen Benutzerdaten (shinosawa:hiro) zugegriffen werden konnte. Die finale Rechteausweitung zu Root erfolgte durch Ausnutzung einer fehlerhaften `sudo`-Konfiguration, die es erlaubte, eine spezifische Datei auszuführen, welche durch eine eigene Shell ersetzt werden konnte (Path Hijacking).

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `netdiscover`
*   `nmap`
*   `nikto`
*   `feroxbuster`
*   `curl`
*   `dirb`
*   `openssl`
*   Ein benutzerdefiniertes Shellskript zum Brute-Forcen von Passphrasen (unter Verwendung von `openssl`)
*   `openvpn`
*   Standard Linux-Befehle (`vi`, `cat`, `grep`, `awk`, `cut`, `tr`, `sudo`, `ls`, `ip`, `ping`, `ssh`, `file`, `echo`, `chmod`, `mv`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Homelab" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Enumeration:**
    *   IP-Adresse der Zielmaschine (`192.168.2.191`) mit `netdiscover` identifiziert.
    *   `nmap`-Scan offenbarte Port 80 (Apache httpd 2.4.62), der auf einen Mac OS X Server hinwies (Copyright 2009). Der Hostname `homelab.hmv` wurde der `/etc/hosts`-Datei hinzugefügt.

2.  **Web Enumeration & Schwachstellensuche:**
    *   `nikto` und `feroxbuster` wurden zur Enumeration des Webservers eingesetzt. `/service/index.php` wurde als interessanter Endpunkt identifiziert.
    *   Der Quellcode der Webseite lieferte Hinweise auf ein veraltetes System und verschiedene Service-Pfade.
    *   Der Zugriff auf `/service/index.php` war initial gesperrt ("only available for myself").

3.  **Initial Access (IP Spoofing, OpenVPN Konfigurations-Leak & Key Cracking):**
    *   Die Zugriffsbeschränkung auf `/service/index.php` wurde durch Setzen des `X-Forwarded-For: 192.168.2.191` Headers umgangen.
    *   Dies ermöglichte den Zugriff auf eine OpenVPN-Konfigurationsdatei.
    *   Mittels `dirb` wurden im Verzeichnis `/service/` die Dateien `ca.crt`, `client.crt` und der verschlüsselte `client.key` gefunden und heruntergeladen.
    *   Ein Shellskript wurde erstellt, um die Passphrase für `client.key` mittels `openssl` und der `rockyou.txt` Wordlist zu brute-forcen. Die Passphrase `hiro` wurde gefunden.
    *   Mit den Zertifikaten, dem entschlüsselten Key und der IP des Ziels wurde eine `connect.ovpn`-Datei erstellt und eine OpenVPN-Verbindung aufgebaut (erhaltene IP: `10.8.0.2`).

4.  **Post-Exploitation / Privilege Escalation (von VPN zu shinosawa):**
    *   Das VPN-Gateway `10.8.0.1` wurde gescannt (Port 80 offen).
    *   Ein `nmap`-Scan des über VPN gepushten Netzwerks `10.176.13.0/24` identifizierte den Host `10.176.13.37`.
    *   Ein weiterer `nmap`-Scan auf `10.176.13.37` zeigte offene Ports 22 (SSH) und 80 (Apache).
    *   Erfolgreicher SSH-Login als Benutzer `shinosawa` mit dem Passwort `hiro` (Passphrase des VPN-Keys) auf `10.176.13.37`.
    *   Die User-Flag wurde im Home-Verzeichnis von `shinosawa` gefunden.

5.  **Privilege Escalation (von shinosawa zu root):**
    *   Die Ausgabe von `sudo -l` zeigte, dass der Benutzer `shinosawa` die Datei `/home/shinosawa/deepseek` ohne Passwort als `ALL` ausführen darf.
    *   Die Originaldatei `deepseek` wurde umbenannt.
    *   Eine neue Datei namens `deepseek` wurde im Pfad `/home/shinosawa/` erstellt, die den Inhalt `ash` (die Shell des Benutzers `shinosawa`) enthielt und ausführbar gemacht wurde.
    *   Durch Ausführen von `sudo /home/shinosawa/deepseek` wurde aufgrund des Path Hijackings eine Root-Shell erlangt.
    *   Die Root-Flag wurde im Home-Verzeichnis des Root-Benutzers gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Veraltete Software:** Der Einsatz eines Mac OS X Servers von ca. 2009 deutete auf potenziell viele bekannte Schwachstellen hin.
*   **IP Whitelisting Bypass (X-Forwarded-For):** Eine interne Ressource (`/service/index.php`), die nur für localhost zugänglich sein sollte, konnte durch Manipulation des `X-Forwarded-For` HTTP-Headers erreicht werden.
*   **Preisgabe von OpenVPN-Konfigurationsdateien:** Sensible Dateien wie Zertifikate und ein verschlüsselter privater Schlüssel waren zugänglich.
*   **Schwache Passphrase für privaten Schlüssel:** Der `client.key` war mit einer leicht zu erratenden Passphrase (`hiro`) geschützt, die via Brute-Force ermittelt werden konnte.
*   **Sudo Fehlkonfiguration (Path Hijacking):** Eine `sudo`-Regel erlaubte die Ausführung einer spezifischen Datei. Indem die Originaldatei umbenannt und eine neue Datei mit demselben Namen und schadhaftem Inhalt (Shell-Aufruf) erstellt wurde, konnten Root-Rechte erlangt werden.

## Flags

*   **User Flag (`/home/shinosawa/user.flag`):** `flag{38665d1048af82499c6ecbd3c0db3acc}`
*   **Root Flag (`/root/root.flag`):** `flag{e3b081b8af1c7079049b029c7cb8bd0d}`

## Tags

`HackMyVM`, `Homelab`, `Medium`, `OpenVPN`, `IP Spoofing`, `Key Cracking`, `Sudo Exploitation`, `Path Hijacking`, `Linux`, `Web`, `Privilege Escalation`
