# Threat-Intelligence-Card


## <strong><bold>Summary:</bold></strong>

 * This Threat Intelligence Card was part of one of the Homework during a cybersecurity program at Rice University.
 
 * It is based on a scenario where a phishing email leads to ransomware.
 
 * I played as part of a Computer and Incident Response Team (CIRT), responsible for compiling Threat Intelligence as part of an incident report.
 
 ## <strong>Tools Used</strong>:
 
 Security Onion | Sguil | Snort | Network Traffic Analysis | Virustotal | Threat Detection/Mitigation
 
 
  ## <strong>Report</strong>:
  
  
Locate the following Indicator of Attack in Sguil based off of the following:

* Source IP/Port: `188.124.9.56:80`
* Destination Address/Port: `192.168.3.35:1035`
* Event Message: `ET TROJAN JS/Nemucod.M.gen downloading EXE payload`


What was the adversarial motivation (purpose of attack)?


* To download a trojan file to infect the victim device with a malware
* Ransomware the target to get financial gain



## <strong>Threat Intelligence Card</strong>:


Describe observations and indicators that may be related to the perpetrators of the intrusion. Categorize your insights according to the appropriate stage of the cyber kill chain


| TTP  | Example   | Finding |
|---|---|---|
|  Reconnaissance | How did the attacker locate the victim? | Google search, job listing, ect   |
| Weaponization  |  What was it that was downloaded? | malicious javascript code   |
|  Delivery | How was it downloaded? |  Via zip or pdf attachment in a phishing email.  |
| Exploitation  | What does the exploit do? |  Create a random files by obfuscated JAVA script in the %TEMP% folder with the extension .exe  |
|  Installation | How is the exploit installed? | After creating the files it uses the GET method and other method to download binary payload from URL  |
| Command & Control (C2)  |  How does the attacker gain control of the remote machine? | it connect to the host remotely on port 80  |
|  Actions on Objectives | What does the software that the attacker sent to do to complete its tasks?  |  Encrypt the files and demand payment, attempts to steal password and personal information, record information about the victim |



## Recommended Mitigation Strategies

* More resrvation about what information can be shared about the company in the Job listing and the Public internet
* Backup your data and test your backup regularly  
* Enable email security tool and email firewall to detect phishing emails and external emails  
* Security awareness training & phishing simulations
* Install the latest version of anti malware
* Set alert and monitor traffic inbound and outbound the network



List of third-party references: 

* https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=JS/Nemucod
* https://www.microsoft.com/en-us/wdsi/threats/malware-encyclopedia-description?Name=TrojanDownloader:JS/Nemucod
* https://www.cisecurity.org/blog/malware-analysis-report-nemucod-ransomware/






