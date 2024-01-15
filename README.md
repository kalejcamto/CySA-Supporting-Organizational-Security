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

        * Adversary: GreenSky27
        * Capabilities: Malware, Post-infection tools, and utilities exploit kits
        * Victim: International, public and private organizations in the Energy sector
        * Infrastructure: Attacker’s registered domains, Global Command & Control Infrastructure, and Chinese Dynamic DNS Infrastructure Providers

 * Kill Chain: As part of the intelligence-driven defense, Cyber Kill Chain or Kill Chain that helps you identify the steps that the attackers must perform to be able to conduct an attack. It lists a series of steps that the attackers must perform as part of the attack. Using the Cyber Kill Chain, you can identify and prevent cyberattacks on your infrastructure. Using Cyber Kill Chain, you can gain insights into the attackers’ methods and procedures that can be used for conducting an attack.

There are various stages or phases in the Cyber Kill Chain. 
The breakdown of each of the stage is as follows:

1. Reconnaissance: Identifying and selecting the target
2. Weaponization: Creating a package with the malware and deliverable payload
3. Delivery: Sending the malicious package to the target system via E-mail or any other methods, such as USB or Website
4. Exploitation: Triggering the malicious package after delivering it to the target’s system
5. Installation: Installing the backdoor for easy persistent access to the target’s system
6. Command & Control: Initiating the communication with the target’s system using an external system and managing the system
7. Actions on objectives: Meeting the objective by exfiltrating data or spreading to the other systems

Detection methods for each stage:

 1. Reconnaissance: Web analytics
 2. Weaponization: Network Intrusion Detection System (NIDS)
 3. Delivery: Alert user
 4. Exploitation: Host Intrusion Detection System (HIDS)
 5. Installation: Host Intrusion Detection System (HIDS)
 6. Command & Control: Network Intrusion Detection System (NIDS)
 7. Actions on objectives: Audit log

  ## Exercise 2 - Threat Research
Assume a scenario in which a malware attack has taken place on a file server. After the attack has been determined, you have found traces of the malware in the log files, which contain events related to malware. It is then your responsibility to research said threats for possible remediation.

In this exercise, I will discuss Threat Research action points in more detail.

  ### Use the Common Vulnerability Scoring System (CVSS) 
  When you find several vulnerabilities within an infrastructure, you would probably not know how to rank them or assign scores to them. CVSS helps you assign a score to each of vulnerability.

For example, you may have a vulnerability that is a risk to the confidentiality, integrity, and availability of your data. Using CVSS, you can determine the score of such.

Scores are calculated based on several metrics. Once you define these metrics, you would be able to determine the CVSS score of a vulnerability. For example, a score of 10 to a vulnerability would make it severe. You can also use CVSS calculators that can help you calculate the scores.

Using Microsoft Edge in Win10, I go to https://www.first.org/cvss/calculator/3.0
![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/00ffe4d4-f11b-415a-82ed-8331ed4cae93)

I scrolled down and selected these paramethers and I receive 5 medium rate.
![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/c35a8983-ea70-4f87-91a3-b521ec8ca899)


  ### Indicators of Compromise (IOC) : IoC can be of various types. Some of these are:

  * Unusual network traffic, either inbound or outbound
  * Unusual activities performed by an administrative or privileged user account
  * Unusual changes in the operating system or registry
  * Unusual connections established from
  * Unusual DNS modifications and requests
  * Untimely system patching

  ## Exercise 3 - Threat Modeling Methodologies
Threat modeling methodology is a method using which an organization can identify potential threats and provide insights to implement appropriate security controls to mitigate these threats.

These methodologies can help a great deal to identify the absence of appropriate security controls due to which several threats can emerge within an organization.

When completing this module I was able to understand: 
After completing this module, you will have further knowledge of:

 #### 1. Adversary Capability
 A capability is someone’s ability to perform a particular task. For example, an electrician can install electrical systems and fix them as and when required. Similarly, an adversary can also have different levels of capabilities. Each adversary may differ in terms of capability. For example, an adversary may have the capability to break into a system but may not have the capability to exploit the vulnerabilities in a Web application.
 A generic set of capabilities is as follows:

    * Unsophisticated: script kiddies
    * Limited: Spammers, politically motivated groups, insiders
    * Moderate: Patriotic hackers, organized gangs
    * Significant: Intelligence service, military intelligence groups
    * Advanced: Nation-state, groups with sophisticated knowledge

 
 #### 2. Total Attack Surface
 An attack surface is like an entry point that can be used by an attacker to get into the network of an organization. It is a vulnerable point that can be exploited by a threat actor. An attack surface can also be a vulnerability that can be exploited.

An organization can implement security controls to reduce an attack surface. Often, organizations make mistakes by implementing several security controls that are not required. This causes the infrastructure or the network to become complex, which leads to administrative issues and can also increase vulnerabilities.

The attack surface can be logical or physical. For an organization to reduce the attack surface, it should limit its physical and logical infrastructure.

To be able to do this, the organization must first identify the assets within the infrastructure and then conduct a threat analysis of these assets. After this, an organization should ensure that the risks and threats are eliminated by implementing security controls or even by removing the unwanted assets.
 
 
 
 #### 3. Attack Vector
 A Threat Agent is someone who conducts an attack. Threat agents can use various methods in an attack. For example, a threat actor can exploit a vulnerability in an attack. The methods or techniques used by the threat actor are known as a threat or attack vector.

Different types of attack vectors can be used by a threat actor. For example, a threat actor can simply exploit the vulnerabilities. Another threat actor may use social engineering methods to get into an organization.

Some of the key examples of threat vector are:

    Unpatched vulnerabilities
    Brute force/cracking
    Distributed denial-of-service (DDoS)
    Domain Shadowing or hijacking
    Credential reuse


#### 4. Impact
The impact of the threats will vary from case to case. Depending on the type of vulnerabilities and the criticality of the asset, the impact will differ. If there is a vulnerability in a critical asset, the impact can be severe in such cases. If there is a vulnerability in a non-critical asset, its impact may not be severe.

#### 5. Likelihood
Threat likelihood is the probability of a threat to occur as there will be a possibility that some threats are more likely to occur than others. You can determine the likelihood of a threat to occur by using some of the possible methods:

    * Reviewing historical statistics
    * Reviewing asset criticality
    * Reviewing vulnerabilities within an asset
The likelihood of a threat to occur can be determined as:

    * Very high
    * High
    * Moderate
    * Low
The definition of each of the likelihood may differ from an organization to an organization.

## Exercise 4 - Threat Intelligence Sharing with Supported Functions 
Threat intelligence is a method or process used by an organization to gather and analyze information that they have either faced in the past or are likely to face in the future. Threat intelligence helps an organization to gain insights into different types of threats and the impact of such.

Based on the intelligence gathered, an organization can prepare for the defense mechanism accordingly.
Incident Response
In an organization, you can face several types of incidents which are likely to be unwanted and unauthorized. For example, a user is attempting to access a restricted folder, or a user is copying confidential files on a USB drive. Both of these incidents can be considered as unwanted and unauthorized.

An incident can also be a technical problem, such as a hard drive failure or an application failure. Different organizations may have different definitions of an incident. With whichever definition an organization goes by, a response to both the incidents is required. When you encounter an incident, you have to respond to it.

Incident response is part of the incident management process, which focuses on managing and preventing incidents from reoccurring. It is a framework that performs the following functions:

    * Detect
    * Report
    * Assess
    * Respond
    * Deal
Incident Management focuses on restoring operations after an incident occurs. The key focus of Incident Management is to minimize the impact of incidents on users, systems, and overall business operations.

Incident handling is about coordination between different functions within an organization to resolve an incident and reduce it’s impact. While Incident Management is the umbrella term, Incident Handling is part of Incident Management. Incident Response is of the functions that are performed under Incident Handling, which has four key functions:
![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/825407c1-2556-4d6a-a3c2-a0fd2d215b49)

Incident Response requires necessary actions to be taken to resolve incidents and involves five steps that play a key role in resolving incidents. These five steps can be applied in any incident response situation:

#### > Initial Reporting and Diagnosis:
An incident by a user is reported to the entities like Technical Support, which provides the answers to the problem.
Incident Escalation: If the initial response to the incident (or troubleshooting) does not work, then the incident is escalated to the next level or another team. This could be some cases, but most of the issues should be resolved by the first level of support to whom the user reports the incident.
An escalation of the incident can either be functional or hierarchical. Functional escalation is with the team that is more knowledgeable and is usually the second-line support. The hierarchical escalation is handled by the senior IT staff with more knowledge. They are usually a separate team within the organization who are trained to handle critical incidents that cannot be handled by frontline or second-line support teams.

#### > Investigation and diagnosis:
In this particular step, the team handling the incident takes a deep dive into the incident and tries to understand what needs to be done to resolve it. After incident investigation is performed and it is diagnosed, a solution is applied. The nature of the solution depends on the type of incident. For example, replacing hardware can be a solution if the incident involves hardware failure.
Resolution and Recovery: In this step, testing is performed to ensure that the resolution applied is working. If testing is successful, then the services are recovered to the normal function.
Incident closure: In this step, the team handling the incident marks the incident as closed.

#### > Vulnerability Management:
A vulnerability is a weakness that may exist within an operating system or applications. A threat actor exploits the vulnerability to cause damage to the system or gain access and control the system. The Vulnerability Management process is about finding vulnerabilities within a system and then remediating them to prevent the threat actor from exploiting them.

There are three parts of to a vulnerability:

The weakness that causes the vulnerability
Threat actor’s access to the vulnerability
Threat actor’s ability to exploit the vulnerability using a tool
In between finding and closing vulnerabilities, several steps should be followed. Vulnerabilities are discovered using an automated tool, which runs the defined baseline on the assets to discover the vulnerabilities.

The steps in the Vulnerability Management Life Cycle are described below.

#### > Discover: 
In the discovery step, you need to first identify hosts and devices on the network. Once this is done, you need to create baselines for these devices and systems. You need to then run the baselines against the systems and devices to discover security vulnerabilities.

#### > Prioritize Assets: 
An organization will contain hundreds to thousands of assets. You need to then categorize the assets based on their criticality factors.
Assess: You will then need to create a baseline risk profile to further eliminate the risks.

#### > Report: 
Based on the baseline risk profile, you need to now measure risks for the assets. You also need to create a security plan to mitigate the risks and vulnerabilities that may have been located.

#### > Remediate: 
You will need to then prioritize the vulnerabilities and fix them accordingly. The low priority vulnerabilities can be handled later, but the high priority vulnerabilities need to be handled with immediate attention.

### > Verify: 
After remediation, you need to ensure that the vulnerabilities have been eliminated. This can be verified through the re-running the assess step and verifying if all vulnerabilities have been closed.

### Risk Management
Over the last decade, there has been wide adoption of technology in day to day work, be it personal or official. With the wide use of technology, the risks relating to technology have also emerged.

There have been risks that have caused businesses to fail because of different types of attacks. It is inevitable that any organization will be risk-free or will not face risks. However, an organization is well prepared to handle risks if they have adopted the principles of risk management.

In the old days, if any organization had adopted risk management principles, it was only the IT team that was dealing with them. However, with the technological developments and adoption, risk management cannot only be left to the IT teams within an organization.

Several entities, including the senior management, should be involved in the risk management, which can help an organization to understand the risks and weaknesses within the processes and systems. It can also help to identify the risks that an organization is exposed to.

Risk Management is an iterative process, which requires the organization to keep reviewing the Risk Management plans and update them from time to time. The organization must:

Understand and know the assets that need to be protected
Know how to protect the assets
Know if an adopted approach is sufficient or adequate
Monitor and improve controls based on the risk evaluation
Risk Management cannot be static. This is because the risks will evolve from time to time within an organization. The organization must continue to evaluate risks and accordingly perform Risk Management, which needs to be an iterative process.

With the help of Risk Management, the organization can plan to minimize risks or the losses that may occur due to the risks. With Risk Management, an organization can gain the ability to make better decisions.

There are four key recurring phases in Risk Management cycle:

![image](https://github.com/kalejcamto/CySA-Supporting-Organizational-Security/assets/101201140/23c7e29e-fb42-4404-8071-898800868969)

In the Risk Management process, you have to perform six key steps. These are:

Categorize information systems: An organization categorizes systems based on its usage and business objectives.
Select security controls: The organization then identifies the security controls to be implemented to safeguard identified systems.
Implement security controls: The security controls are implemented to safeguard the systems and networks.
Assess security controls: In this step, the security controls are assessed for their weaknesses. A detailed report is generated based on the assessment.
Authorize Information Systems: Based on the report, an action plan is created to handle the weaknesses in the security controls.
Monitor security controls: With the changes in the security controls, the organization needs to determine the security impact. This is a step where continuous monitoring of the changes should take place.

### Security Engineering
Security engineering is a focus field that intends to build robust systems that can handle any type of unwanted incident, such as a natural disaster or a malicious act.

Security engineering works in the same manner as any other engineering stream, but it has an added responsibility of building robust systems that can handle the misuse of incidents.

Security Engineering, a person is required to be equipped with cross-disciplinary expertise. Some of the cross-disciplinary expertise are:

    Cryptography
    Software Development
    Security software tools
    Security hardware
    
When you refer to security engineering, it is about integrating security into the engineering processes. Security, in this regard, is not an isolated domain but rather an integrated domain within the engineering domain.

When an organization is engineering a product, the security must be integrated at the time of development. When security is integrated at the time of development, several vulnerabilities can be prevented and avoided being built into the product. If security engineering is not into the product building, then it may include several vulnerabilities, which if discovered later, can lead to a huge cost in fixing the vulnerabilities.

The key intent of security engineering is to integrate security controls into every part of the development as well as the part of the information systems. This way, security is deep-rooted into the products and the information systems. An organization does not need to re-create the concept of security engineering. It can simply adopt the concepts from the following standards:

NIST Special Publication 800-27 Revision A
DHS Software Assurance Workgroup, Software Assurance 
DoD Information Assurance Technology Analysis Center, Software Security Assurance
ISO/IEC 15026, Systems and Software Engineering: Systems and Software Assurance
Detection and Monitoring
Threat detection is the method using which an organization can scan an entire information system to detect any threats. If a threat is detected, then the organization needs to put in efforts to mitigate it. It could be as simple as ignoring the threat and as complex as the organization putting in security controls to tackle it.

Organizations face significant challenges when dealing with a breach. Not only do they risk damaging their reputation, but they also face the loss of data and potential legal liability To mitigate these risks, many organizations invest in threat detection efforts to reduce the likelihood of a breach.

However, organizations often introduce complex security controls in an attempt to enhance their security. Unfortunately, this complexity can make infrastructure management more difficult Additionally, the increased number of controls can inadvertently introduce more vulnerabilities that are challenging to detect due to the complexity Therefore, it is crucial for organizations to strive for simplicity in their infrastructure and security controls while prioritizing continuous monitoring and threat detection.

Rather than waiting for threats to materialize, security teams should proactively focus on detecting and mitigating threats. This requires continuous monitoring and evaluation of all aspects of the infrastructure, including endpoints By promptly identifying and neutralizing threats, organizations can minimize the potential exploitation of vulnerabilities.

In summary, organizations must prioritize threat detection and invest in continuous monitoring to effectively address breaches. Simplifying infrastructure and security controls can help mitigate complexity-related challenges and enhance overall security.

## To be able to detect threats, the organization should implement solutions that will:

    1. Aggregate events from various network services and devices
    2. Aggregate logs from various network services and devices
    3. Implement threat detection technology
    4. Monitor and analyze the traffic continuously
    5. Implement threat detection technology and monitoring the endpoints, which are user systems
