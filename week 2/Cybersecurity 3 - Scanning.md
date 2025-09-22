# Cybersecurity 3 - Introduction ❔  
  
**Terminologie** 🧠  
- [ ] red teaming  
	- aanvaller die probeert in te breken zonder dat het IT departement dit weet  
- [ ] blue team  
	- de verdedigende kant van cybersecurity   
- [ ] purple teaming  
	- combo van **red **en **blue **werken beide teams samen   
		* attackers tonen hun technieken  
		* defenders leren direct hoe ze die kunnen detecteren en blokkeren  
- [ ] penetration testing (pentesting)  
	- een gecontrolleerde simulatie van een aanval, pentesters zoeken naar kwetsbaarheden  
- [ ] code review  
	- nagaan of er programmeerfouten in de applicatie zitten  
- [ ] config review  
	- controle van de configuratie van systemen en software   
- [ ] bug bounty  
	- publiek programma waarbij bedrijven hackers uitnodigen om bugs te zoeken  
  
**Blue Team 👮🏻‍♂️**  
- [ ] CSIRT (Computer Security Incident Response Team)  
	* reageert op beveiligingsincidenten  
- [ ] SOC (Security Operations Center)  
	* 24/7 netwerk en systemen monitoren  
- [ ] Threat Intelligence   
	* analyse van aanvallen  
- [ ] Developers  
	* moeten focussen op **secure coding**  
- [ ] Network defenders  
	* beschermet het netwerk door **firewalls, IDS/IPS, monitoring**  
- [ ] Digital forensic analysts  
	* onderzoeken aanvallen achteraf  
- [ ] Vulnerability management  
	* beheerd en prio kwetsbaarheden  
  
**Types of pentesting**  
- [ ] external pentesting  
- [ ] internal pentesting  
- [ ] physical pentesting  
- [ ] perimeter penteting  
- [ ] web application pentesting  
- [ ] mobile application pentesting  
- [ ] infrastructure pentesting  
- [ ] network pentesting  
  
**Hacking Modes **  
- [ ] Black box  
	- tester krijgt **geen info **over doelwit  
- [ ] White box  
	- tester krijgt **gedeeltelijke **informatie over doelwit   
- [ ] Grey box  
	- tussening krijgt **gedeeltelijk **wel/geen informatie  
   
**Malicious hackers 🥷🏿**  
- [ ] script kiddies (onervaren hackers)  
- [ ] suicide hackers (hackers die schijt hebben aan de gevolgen)  
- [ ] hackitivist (hacken om boodschap over te brengen)  
- [ ] Nation states (werken namens land/regering)  
  
**Social engineering (mensen manipuleren)**  
- [ ] reciprocity  
	- mensen voelen zich verplicht iets te doen (Tinder scams)  
- [ ] commitment and consistency  
	- onschuldige enquete en ineens geef je privé informatie  
- [ ] social proof  
	- meelopen met de mensen bv scam —> *‘200 collegas hebben hun ww al veranderd’*  
- [ ] authority  
	- nabootsen van iemand met gezag  
- [ ] liking  
- [ ] scarcity  
	- mensen handelen sneller als er tijdsnood is —> *‘je account wordt binnen 24 uur verwijderd’*  
  
**Methods**  
- [ ] phishing  
- [ ] spear phising  
- [ ] vishing  
- [ ] smishing  
- [ ] impersonation  
  
**Basisconcepten**  
- [ ] **assets**  
**	! **wat beschermen ze? data, intellectuele eigendom, hardware, software  
- [ ] **threats**  
**	! **alles of iedereen die schade kan veroorzaken  
- [ ] **vulnerabilities**  
**	! **zwakke plekken in systemen door een threat misbruikt worden   
- [ ] **risks**  
	**! **is de kans dat een **threat **gebruikmaakt van een **vulnerability**, met negatieve gevolgen  
  
**Pentest methodology**  
1. planning   
2. footprinting & scanning - informatie verzamelen over target  
3. enumeration - vinden van services, users, -en vulnerabilities  
4. exploitation - exploiten van vulnerabilities om access te gainen  
5. post-exploitation - privelege escalation, local enumeration  
6. reporting - feedback van de results  
  
———————————————————————————————————————————————————  
#   
# Cybersecurity 3 - Footprinting 👣  
  
Wat is ***footprinting* **nu?   
- [ ] gedeelte van offense attack waarbij je zoveel mogelijk informatie verzamelt over een bedrijf of doelwit  
  
Dit is de eerste stap van **Reconnaissance **(verkenning) in cybersecurity. Van footprinting heb je **twee types**:  
- [ ] **active: **directe interactie met de target   
**	- **ping sweeps  
	- network mapping  
	- host-discovery  
	- port scanning  
  
- [ ] **passive: **enkel informatie verzamelen alsof je een gewone user bent  
	- surfen op hun website  
	- domein informatie extracten  
	- Robots.txt bevat vaak directories die verborgen of geindexeerd mogen worden   
	- social networks info uithalen op LinkedIn, X enzovoort.  
  
**Google dorks **(Google Hacking) betekent dat je met specifieke **zoekopdrachten **en **operators **in google verborgen informatie kan vinden die niet makkelijk zichtbaar is.  
  
**NS Lookup **is een **DNS **tool die je gebruikt om informatie uit het **Domain Name System **op te vragen. Deze zet zoals je weet ip adressen om naar domains.  
  
**WHOIS **is een protocol waarmee je informatie over domein-naam registraties kan opvragen.   
  
Varia tools & technieken:  
- [ ] zien welke technologie en plugins gebruikt zijn in een website:  
	- browserextensie: BuiltWith, Wappalyzer  
	- linux command tool: **whatweb**  
- [ ] website kopieren  
	- tool: **HTTrack**  
- [ ] subdomain enumeration  
	- tool: **Sublist3r**  
- [ ] checken of **WAF **(Website Application Firewall) aanwezig is  
	- tool: **wafw00f**  
- [ ] website reconnaissance  
	- tool: **netcraft**  
- [ ] email harvesting  
	- tool: **theHarvester**  
- [ ] network scanning  
	- tool: **Nmap**  
**		? -sn **om packets te verzenden om hosts te discoveren (sudo run)  
		**? -v **optie voor een meer informatieve output  
		**? -p **optie om volledige port range te checken  
		**? -F **de 100 meest gebruikte hosts  
		**? -sU **UDP port scan  
  
**TryHackMe - **Pickle Rick   
  
Used commands:  
- [ ]    
  
———————————————————————————————————————————————————  
#   
# Cybersecurity 3 - Scanning 🖨️  
  
Scanning wordt gebruikt om **hosts **te identificeren binnen **ranges**. Daarna volgt pas de **enumeration**, waarbij je onderzoekt welke poorten openstaan en welke services of versies daarvan draaien.   
  
Tijdens het scannen kan je activiteit worden gedetecteerd door **IDS/IPS **(Intrusion Detection/Prevention System). Daarom moet je voorzichtig zijn met scannen en eventueel een proxy gebruiken.  
  
Er bestaan verschillende scanmethodes:  
- [ ] network scan/sweep  
- [ ] port scan  
- [ ] fingerprinting  
- [ ] vulnerability scan  
  
Met een **Network Scan **of **Ping Sweep** kun je ontdekken welke hosts actief zijn in een netwerk.  
	- wat je dan doet is **ICMP **echo requests uitsturen en wachten op **reply**  
  
— **Nadelen:**  
- [ ] veel systemen blokkeren ping default  
- [ ] grote sweeps kunnen **IPS **triggeren  
  
**Ports you should know**  
- [ ] 20  
- [ ] 22  
- [ ] 23  
- [ ] 25  
- [ ] 69  
- [ ] 80  
- [ ] 110  
- [ ] 161 & 162  
- [ ] 443  
  
Bij geavanceerd scannen worden ook kwetsbaarheden opgespoord en risico’s worden geidentificeerd met tool zoals:  
-	**OpenVas**  
-	**Nessus**  
-	**Nexpose**  
-	**Retina**  
  
Ook heb je verschillende **port-states:**  
- [ ] open (luistert naar verbindingen)  
- [ ] gesloten (bereikbaar maar geen service actief)  
- [ ] filtered (geen antwoord door firewall of filtering)  
  
**Nmap **heeft nog extra states:  
- [ ] non-filtered: poort is bereikbaar maar Nmap kan niet bepalen of open of closed  
- [ ] open | filtered: kan niet onderscheiden of ie open of filtered is  
- [ ] closed | filtered: onduidelijk of poort gesloten of filtered is   
  
* **TCP basics**  
    * ***3-way handshake*: **SYN → SYN/ACK → ACK om een verbinding op te zetten.  
    * ***TCP flags*: **speciale bits (SYN, ACK, FIN, RST, PSH, URG) die het gedrag van een verbinding bepalen.  
* **Veelvoorkomende scanning technieken**  
    * **Full/Open scan (Connect scan)** → volledige handshake uitvoeren; betrouwbaar, maar makkelijk te detecteren.  
    * **Stealth/half-open scan (SYN scan)** → alleen SYN en SYN/ACK; verbinding nooit volledig, moeilijker te detecteren.  
    * **Xmas Tree scan** → stuurt een pakket met meerdere flags (FIN, URG, PSH); reacties kunnen info over OS en poorten verraden.  
    * **FIN scan** → alleen FIN-flag; vaak firewall-omzeilend, geen antwoord = poort open of gefilterd.  
    * **Null scan** → stuurt pakket zonder flags; gedrag van host bepaalt of poort open/gesloten is.  
    * **Idle scan** → gebruikt een “zombie”-host om zeer stealthy te scannen zonder eigen IP bloot te geven.  
    * **ACK scan** → controleert of een firewall aanwezig is en of poorten gefilterd zijn.  
  
Verschil tussen **FIN/RST**  
- [ ] FIN - Finish: sluit de verbinding netjes af (2 way handshake)  
- [ ] RST - Reset: beeindigt een verbinding onmiddelijk  
  
Verschil tussen **PSH/URG**  
- [ ] PSH - Push flag: data word normaal in buffer, maar PSH 1 direct naar applicatielaag  
- [ ] URG - Urgent flag: samen met urgent pointer gebruiken om data als urgent te markeren   
  
## 🔎** TCP Scanning technieken (samenvattingen)**  
**Full/Open (Connect) Scan**  
* Volledige 3-way handshake.  
* Betrouwbaar, maar traag en makkelijk te detecteren (IDS).  
* Resultaat: handshake voltooid = open, RST = gesloten.  
**SYN Scan (Half-open/Stealth)**  
* Alleen eerste 2 stappen van de handshake.  
* Minder zichtbaar in logs, snel.  
* Resultaat: SYN+ACK = open, RST = gesloten, geen reactie = gefilterd.  
**Xmas Tree Scan**  
* Zet FIN, URG en PSH flags tegelijk (illegale combinatie).  
* Meestal genegeerd, soms reactie → kan OS info onthullen.  
* Resultaat: RST = gesloten, geen antwoord = open/gef.  
**FIN Scan**  
* Stuurt FIN-flag om connectie te sluiten.  
* Kan firewalls omzeilen.  
* Zelfde interpretatie als Xmas Scan (RST = gesloten, geen antwoord = open/gef.).  
**Null Scan**  
* Stuurt pakket zonder flags.  
* Resultaat: RST = gesloten, geen reactie = open/gef.  
**Idle Scan**  
* Zeer stealthy: gebruikt een “zombie”-host als tussenstation.  
* Aan de hand van **IP ID’s** van zombie kan open/gesloten poort bepaald worden.  
* Verbergt de identiteit van de aanvaller.  
**ACK Scan**  
* Test niet of poort open is, maar of een **firewall** actief is.  
* RST = poort on-gefilterd (kan open of dicht zijn).  
* Geen reactie of ICMP error = poort gefilterd.  
  
## 🔎** UDP Scanning**  
* UDP is *connectionless* (geen handshake, geen flags).  
* Werking: stuur UDP-pakket → analyseer reactie.  
* Resultaten:  
    * ICMP port-unreachable = gesloten  
    * ICMP error (type 3 codes 1,2,9,10,13) = gefilterd  
    * Geen reactie = open (of gefilterd)  
  
## 🖥️** Fingerprinting**  
* Doel: besturingssysteem en services identificeren via pakketkenmerken.  
* **Active**: zelf crafted packets sturen, vergelijken met database → sneller, maar detecteerbaar.  
* **Passive**: enkel sniffen, TTL & TCP-window size analyseren → stealthy maar trager.  
* Voorbeeld (Active): nmap -O <IP>  
* Voorbeeld (Passive): Linux TTL = 64, Windows XP TTL = 128.  
  
## 🛡️** Defense tegen scanning**  
* **Disconnect** bij aanval.  
* Gebruik enkel **geharde** applicaties/OS.  
* **Automatische updates** activeren.  
* **DMZ’s** inzetten om interne netwerken te beschermen.  
* **IPS** installeren (Intrusion Prevention).  
* Zelf regelmatig **vulnerability scans** doen en problemen patchen.  
  
dcsdc  
