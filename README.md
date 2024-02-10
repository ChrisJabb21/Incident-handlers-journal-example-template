# Incident-handlers-journal-example-template
A template for an incident handler's journal template. Entries were created as part of exercises for coursework on the Coursera Google Cybersecurity Professional certificate track.  

## Incident Details

- **Date and Time**: [Insert Date and Time]
- **Incident ID**: [Insert Unique Identifier]
- **Description**: [Brief description of the incident]

## Investigation Steps

| Step | Action Taken | Outcome |
|------|--------------|---------|
| 1    | [Describe the action taken during this step] | [Result or findings] |
| 2    | [Describe the action taken during this step] | [Result or findings] |
| ...  | ...          | ...     |

## Evidence and Artifacts

- Attach relevant files, logs, screenshots, or other evidence here.

## Recommendations

- Provide recommendations for mitigation, prevention, or further investigation.

## Follow-Up Actions

- List any follow-up tasks or actions required.


## List of Entries


### Entry #1

- **Date and Time**: 08/01/2023, Tuesday morning, 9:00 AM.
- **Incident ID**: 01
- **Description**: An incident occurred for a small U.S. health care organization where employee workstations were infected with ransomware as part of a sophisticated cyberattack done by an organized group of unethical hackers. The incident investigation is within the Detection and Analysis and Containment, Eradication, & Recovery of the NIST Incident Response Lifecycle.
-  **Tools used** : NA 


| Step | The 5 W's | Outcome |
|------|--------------|---------|
| 1    | **Who** caused the incident? | An organized group of unethical hackers known for targeting organizations in healthcare and transportation industries. |
| 2    | **What** happened? | Several employees reported they were not able to use their computers to  access work related files. A ransom note was displayed on their computers that the group responsible had encrypted the employees files and demanded a large sum of money in exchange for the decryption key to recover the data on infected computers. Business operations for the health care clinic were forced to shut down and disrupted because employees were unable to access files and software needed to do their jobs.  |
| 3    | **When** did the incident occur?          | It occurred early Tuesday morning and was reported at 9:00AM by the organization for technical assistance to respond to the incident.|
|  4   |   **Where** did the incident happen? | A small U.S. health care clinic specializing in delivering primary care services.|
|  5   | **Why** did the incident happen? |The cause of the incident was a phishing email containing a malicious attachment crafted by the hacker organization that deployed the ransomware when downloaded and opened by targeted employees that encrypted their files and made demands for money to return the files back to normal.|
---

- **Additional notes**: In the event of an incident similar to this one occurs, the following precautions need to be considered
   - How can the organization prevent an incident like this from happening again?
   - Should the company pay the ransom to retrieve the decryption key? 
   - Are there any tactics or controls in place to help the organization deal with mitigating and recovering from Ransomware attacks? (e.g. restoring systems from previous backups)
 


### Entry #2

- **Date and Time**: 08/04/2023 1:20 PM
- **Incident ID**: 02
- **Description**: This incident investigation stage is within the Detection and Analysis phase of the NIST Incident Response lifecycle. A suspicious file downloaded on an employee’s computer is investigated and analyzed to capture details and find indicators of compromise (IoCs) within the file which is called “bfsvc.exe". The file is retrieved and converted into a SHA256 hash for malware analysis.
-  **Tools used** :
    -   VirusTotal tool to analyze SHA256 file hash of the malicious file
    -   MalwareBazaar from abuse.ch to check malware sample and crowdsourced information on hash file.



| Step | The 5 W's | Outcome |
|------|--------------|---------|
| 1    | **Who** caused the incident? | A sender with the email address of  76tguyhh6tgftrt7tg.su  and an IP address of 114[.]114[.]114[.]114. A threat actor with access to previously reported malware called Flagpro used by the Chinese cyber espionage APT group or state actor hackers known as BlackTech. The group has primarily targeted organizations in East Asia (e.g. Taiwan, Japan, and Hong Kong) and English-speaking countries to compromise media, construction, engineering, electronics, and financial company networks. |
| 2    | **What** happened? | The threat actor sent a spear phishing email with a password protected file attachment to an employee and the password to open the file in the same email. The employee downloads and opens the file with the password, multiple unauthorized executable files are created on the employee’s computer. |
| 3    | **When** did the incident occur? | The incident occurred at 1:20PM, the time an intrusion detection system found the executable files and sent out the security alert to the organization’s SOC. The timestamps details leading to the event are in the additional notes of this journal entry.|
|  4   |   **Where** did the incident happen? | A financial services company based in the United States. |
|  5   | **Why** did the incident happen? | The threat actor was able to trick the employee into downloading and executing the malware through a spear phishing email attempt based on their target organization and the presence of several unauthorized files from the downloadwere detected by an IDS in place and an alert was sent out to the organization’s SOC for investigation.|
---

- **Additional notes**:

- A timeline of the events leading up to this alert:
  -  1:11 p.m.: An employee receives an email containing a file attachment.
  -  1:13 p.m.: The employee successfully downloads and opens the file.
  -  1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.
  -  1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.


-------------------------------
Email content:

From: Def Communications <76tguyhh6tgftrt7tg.su>  <114[.]114[.]114[.]114>
Sent: Wednesday, July 20, 2022 09:30:14 AM
To: <hr@inergy[.]com> <176[.]157[.]125[.]93>

Subject: Re: Infrastructure Egnieer role  :warning: WARNING  _typos present in subject_

Dear HR at Ingergy, :warning: WARNING  _typo present in company name_

I am writing for to express my interest in the engineer role posted from the website.

There is attached my resume and cover letter. For privacy, the file is password protected. Use the password paradise10789 to open.  :warning: WARNING _file is password protected and the password is given._ 

Thank you,

Clyde West

Attachment: filename="bfsvc.exe" :warning: WARNING _(payload is an executable file)_

-----------------------------------------------

The suspicious file’s filename: _**bfsvc.exe**_

The suspicious file’s SHA256 hash value: **54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b**


Steps to resolution:
-  Update the alert ticket status from open to investigating
-  Review the phishing Playbook and flowchart in place 
-  Determine if the link(s) or attachment(s) in the email are malicious
-  A summary of the findings are written based on the type of danger the links or attachments may be capable of.
-  Escalated the status of the ticket based on danger posed by email attachment.



VirusTotal and MalwareBazaar both score this file with negative community scores which means the file is indeed malicious. The executable is reported to be a type of Trojan malware and is referenced in the links below.

Links for reference:

- [Flagpro: The new malware used by BlackTech | NTTセキュリティテクニカルブログ (security.ntt)](https://attack.mitre.org/software/S0696/)
- [Flagpro, Software S0696 | MITRE ATT&CK®](https://attack.mitre.org/software/S0696/)
- [BlackTech, Palmerworm, Group G0098 | MITRE ATT&CK®](https://attack.mitre.org/groups/G0098/)

File Analysis results
- [VirusTotal - File - 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b](https://www.virustotal.com/gui/file/54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b/summary)
- [MalwareBazaar | SHA256 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b (BlackTech) (abuse.ch)](https://bazaar.abuse.ch/sample/54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b/#iocs)





##  Reflections/Notes

_Were there any specific activities that were challenging for you? Why or why not?_
The most challenging activities for me was in incident entry #4 with getting access to my Splunk Cloud instance so I can set up  the test environment. I also had some difficulties with providing too much information at times for all my incident journal entries and making sure I kept my log entries short but informative and with resource insights.

_Has your understanding of incident detection and response changed since taking this course?_
It has grown to be much more greater understanding with getting to do the hands-on challenges provided within the course to test what I have learned. It made me challenge myself and got me out of my comfort zone in a good way to show the work a cybersecurity professional does and get experience

_Was there a specific tool or concept that you enjoyed the most? Why?_

I really loved and enjoyed using the VirusTotal and MalwareBazaar tools to investigate a suspicious email attachment to determine if it was malicious or not. It really sparked alot of interest in me as I found threat hunting to be just like being a cyber detective looking for clues within a case and to leave no stone unturned in making a final decision of if there is a possible threat. 

It felt to me like a treasure hunt but with the twist of keeping organization systems as well myself safe from malicious attempts to attack or disrupt computer systems and networks. I was always fascinated with malware analysis in general and learning how malware can be used to attack and compromise systems and to find ways to stop them.

