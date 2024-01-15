# CySA-Supporting-Organizational-Security
In this CySA lecture and lab I was able to learn more about. MITRE ATT&amp;CK The Diamond Model of Intrusion Analysis Kill Chain Indicator of Compromise (IOC) Adversary Capability Total Attack Surface Attack Vector Impact Likelihood Incident Response Vulnerability Management Detection and Monitoring Risk Management Security Engineering

Cengage labs virtual machines: 
- Windows Server 2019 - Domain Server
- Windows Server 2019 - Domain Member
- Kali Linux 2019 - Linux Kali
- Windows 10 - Domain Member Workstation
- Alma Linux 8.6 - Stand-alone Linux Workstation
- Alien Vault Linux Security Management Platform

    ## Exercise 1 - Attack Frameworks
Various attack frameworks are available and can be used by organizations to classify attacks and help identify security loopholes within their system. You can use these attack frameworks to identify loopholes and prioritize them based on the risk they pose.

In this exercise, you will see about various types of attack frameworks.
 * MITRE ATT&CK  https://attack.mitre.org/ MITRE gives you a lot of information about different tactics and techniques used by attackers. It also provides mitigation methods for enterprises and mobile devices. The following exhibit provides information for mobile security. You can also find information on software that is used in attacks. An example of AndroRAT is given below.
   ![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/87ee51dd-72b6-4fa1-959a-a1b123c4b1b2)

   
 * The Diamond Model of Intrusion Analysis: The Diamond Model of Intrusion Analysis The Diamond Model helps security professionals to understand how the adversaries work and how they go on to identify the targets. It also helps them to understand the adversary’s capabilities and motives. It is an approach that can be used to conduct intelligence on the intrusion events that occur on the network. A few key examples:

Adversary: GreenSky27
Capabilities: Malware, Post-infection tools, and utilities exploit kits
Victim: International, public and private organizations in the Energy sector
Infrastructure: Attacker’s registered domains, Global Command & Control Infrastructure, and Chinese Dynamic DNS Infrastructure Providers

 * Kill Chain: As part of the intelligence-driven defense, Cyber Kill Chain or Kill Chain that helps you identify the steps that the attackers must perform to be able to conduct an attack. It lists a series of steps that the attackers must perform as part of the attack. Using the Cyber Kill Chain, you can identify and prevent cyberattacks on your infrastructure. Using Cyber Kill Chain, you can gain insights into the attackers’ methods and procedures that can be used for conducting an attack.

There are various stages or phases in the Cyber Kill Chain. These stages are as shown in the exhibit:
The breakdown of each of the stage is as follows:

1. Reconnaissance: Identifying and selecting the target
2. Weaponization: Creating a package with the malware and deliverable payload
3. Delivery: Sending the malicious package to the target system via E-mail or any other methods, such as USB or Website
4. Exploitation: Triggering the malicious package after delivering it to the target’s system
5. Installation: Installing the backdoor for easy persistent access to the target’s system
6. Command & Control: Initiating the communication with the target’s system using an external system and managing the system
7. Actions on objectives: Meeting the objective by exfiltrating data or spreading to the other systems

Detection methods for each stage:

Reconnaissance: Web analytics
Weaponization: Network Intrusion Detection System (NIDS)
Delivery: Alert user
Exploitation: Host Intrusion Detection System (HIDS)
Installation: Host Intrusion Detection System (HIDS)
Command & Control: Network Intrusion Detection System (NIDS)
Actions on objectives: Audit log

  ## Exercise 2 - Threat Research
Assume a scenario in which a malware attack has taken place on a file server. After the attack has been determined, you have found traces of the malware in the log files, which contain events related to malware. It is then your responsibility to research said threats for possible remediation.

In this exercise, I will discuss Threat Research action points in more detail.

  ### Use the Common Vulnerability Scoring System (CVSS) 
  When you find several vulnerabilities within an infrastructure, you would probably not know how to rank them or assign scores to them. CVSS helps you assign a score to each of vulnerability.

For example, you may have a vulnerability that is a risk to the confidentiality, integrity, and availability of your data. Using CVSS, you can determine the score of such.

Scores are calculated based on several metrics. Once you define these metrics, you would be able to determine the CVSS score of a vulnerability. For example, a score of 10 to a vulnerability would make it severe. You can also use CVSS calculators that can help you calculate the scores.

Using Microsoft Edge in Win10, I go to https://www.first.org/cvss/calculator/3.0
![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/00ffe4d4-f11b-415a-82ed-8331ed4cae93)

I scrolled down and selected: 

![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/809f9db1-3adb-4b8c-b5cf-4364871fe4d1)



  ### Indicators of Compromise (IOC) : IoC can be of various types. Some of these are:

  Unusual network traffic, either inbound or outbound
  Unusual activities performed by an administrative or privileged user account
  Unusual changes in the operating system or registry
  Unusual connections established from
  Unusual DNS modifications and requests
  Untimely system patching



