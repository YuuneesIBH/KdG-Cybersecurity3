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
  
  
