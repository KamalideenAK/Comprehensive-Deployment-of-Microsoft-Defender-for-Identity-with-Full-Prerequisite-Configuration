# Microsoft-Defender-for-Identity-MDI

This project documents the end-to-end implementation of Microsoft Defender for Identity (MDI) across a hybrid Active Directory environment. It includes detailed steps for configuring all required prerequisites—covering audit policies, gMSA setup, sensor deployment, network resolution, and security hardening—to ensure optimal threat detection and response.

Key highlights:

✅ Full onboarding of MDI sensors on domain controllers

🔐 Secure configuration of Group Managed Service Accounts (gMSA)

📊 Audit policy tuning for critical event IDs (8004, 1644, 4662)

🌐 Network Name Resolution (NNR) setup for accurate entity mapping

⚙️ SAM-R and Deleted Objects container permissions for lateral movement detection

🧠 Learning period and simulation playbooks for validating detection capabilities

📈 Capacity planning and performance optimization for sensor health

This implementation aligns with Microsoft’s best practices and is validated using readiness scripts and health alert monitoring. 

Ideal for SOC teams, security architects, and compliance-driven environments seeking robust identity protection.

=================================================================================

Enabling Microsoft Defender for Identity (MDI) is a strategic move for protecting your hybrid Active Directory environment from identity-based threats. Here's a clear, step-by-step guide tailored for your enterprise-level deployment.

What Is Defender for Identity?
MDI is a cloud-based security solution that monitors on-premises Active Directory signals to detect suspicious activities, compromised identities, and lateral movement.

Microsoft Defender for Identity MDI (previously called Azure Advanced Threat Protection or Azure ATP) is a Microsoft security solution that captures signals from Domain Controllers. MDI is a cloud-based security solution that leverages on-premises Active Directory signals for detecting identity attacks.

Microsoft Defender for Identity works based on four security pillars:

🛡️ Prevent
- Focuses on reducing attack surfaces before threats occur.
- Identifies vulnerabilities like exposed credentials, legacy protocols, and misconfigured domain controllers.
- Helps harden your environment using posture assessments and proactive recommendations.

🛡️ Detect
- Uses behavioral analytics, machine learning, and deterministic rules to spot suspicious activities.
- Monitors lateral movement, abnormal logins, and privilege escalations in real time.
- Captures signals from domain controllers and VPNs to flag identity-based threats.

🛡️ Investigate
- Provides rich context around alerts, including timelines, impacted entities, and attack paths.
- Enables security teams to trace how threats unfolded across users, devices, and networks.
- Integrates with Microsoft 365 Defender for unified incident views.

🛡️ Respond
- Supports automated and manual actions like disabling accounts, triggering alerts, or integrating with SIEM/SOAR tools.
- Helps contain threats quickly to minimize impact.
- Can be extended with Microsoft Sentinel for orchestration and playbook-driven remediation.

Defender for Identity monitors the domain controllers by capturing and parsing network traffic and using the Windows events directly from the domain controllers. With the use of profiling, deterministic detection, machine learning, and behavioral algorithms Defender for Identity learns from the environment and enables the detection of anomalies.

Defender for identity security posture assessment can detect vulnerabilities such as;

• Exposing credentials in clear text.
• Legacy protocols in use.
• Unsecure Kerberos delegation.
• Dormant accounts in sensitive groups.
• Weaker cipher usage
• Print spooler service in Domain controllers
• Not managing local administrator accounts centrally (Microsoft LAPS)
• Lateral movement paths
• Unmonitored domain controllers
• Unsecure Account attributes
• Unsecure SID history attributes

==============================================================================================

*****Components*****

Defender for Identity consist of the following components:

🧠 Microsoft 365 Defender portal: MDI is integrated into the Microsoft 365 Defender portal.

🧠 Defender for Identity sensor: Sensor is installed on Domain Controllers for monitoring all traffic.

🧠 Defender for Identity cloud services: Separate environment hosted in Azure. MDI cloud service runs on Azure infra and is connected with the security graph.

------------------------------------------------------------------------------------------------------

Defender for Identity viewed from a simplified view. Image source: Microsoft

<img width="1024" height="409" alt="image" src="https://github.com/user-attachments/assets/4c30cce4-70c7-4127-b6fd-6e746012f806" />

=========================================================================================================

The MDI Sensor contains a couple of core functionalities that are critical for getting MDI onboarded. The installed sensor is responsible for the following activity:

1) Capture and inspect domain controller network traffic (local traffic of the domain controller)

2) Receive Windows Events directly from the domain controllers

3) Receive RADIUS accounting information from your VPN provider

4) Retrieve data about users and computers from the Active Directory domain

5) Perform resolution of network entities (users, groups, and computers)

6) Transfer relevant data to the Defender for Identity cloud service

----------------------------------------------------------------------------------------------------------------

🚀 Step-by-Step: Enable Microsoft Defender for Identity

*****Preparation of the environment*****

==============================================================================================================================================================================================================

Step 1: Prepare Your Environment

Licensing is user-based. Common mistake; purchase licenses based on the sensor count. Defender for Identity is user-based counted on the AzureAD users. The following licenses are available;
I) Enterprise Mobility + Security E5/A5

II) Microsoft 365 A5/ E5/ G5

III) Microsoft 365 A5/ E5/ G5/ F5 Security license.

✔️  Ensure you're licensed with Microsoft 365 E5, Microsoft 365 E5 Security, or have purchased Defender for Identity as an add-on.

✔️  Confirm your domain controllers run Windows Server 2016 or later.

✔️  Enable Windows Event Forwarding and configure audit policies as per Microsoft’s recommendations here (https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity)

--------------------------------------------------------------------------------------------------------

🚀 Network

✔️ Sensors able to reach Defender for Identity Cloud service.

✔️ Specific ports allowed from Defender for Identity sensors in the environment.

✔️ Network Name Resolution requirements enabled.

----------------------------------------------------------------------------------------------------------

🚀Audit

***Enable audit policies***

✔️   Enable audit policies for Event ID 8004
✔️   Enable audit policies for Event ID 1644
✔️   Enable object auditing
✔️   Enabled optionally exchange auditing

*****Enable audit events****

Defender for Identity relies heavily on Windows Event log entries to enhance detections and provide additional information. It is needed to assign the recommended audit event policy to the Domain Controllers.

Recommended is to not use the built-in Domain Controllers policy and create a separate policy.

Windows Event collection: 
On the server/Domain Controller, Go to : Computer Configuration > Policies > Windows Settings > Security Settings -> Advanced Audit Policy Configuration > Audit Policies

Configure the following table for success and failure:
Audit policy	Subcategory	Triggers event IDs : 

🛡️ Account Logon	Audit Credential Validation	4776

🛡️ Account Management	Audit Computer Account Management	4741, 4743

🛡️ Account Management	Audit Distribution Group Management	4753, 4763

🛡️ Account Management	Audit Security Group Management	4728, 4729, 4730, 4732, 4733, 4756, 4757, 4758

🛡️ Account Management	Audit User Account Management	4726 

🛡️ DS Access	Audit Directory Service Access	4662 – For this event. Object auditing is needed

🛡️ DS Access	Audit Directory Service Changes	5136

🛡️ System	Audit Security System Extension	7045

🛡️ Additional configure Exchange auditing when Exchange is currently configured.


Example configuration for audit computer account management:

<img width="1024" height="543" alt="image" src="https://github.com/user-attachments/assets/6b379749-5169-4746-89b6-4f68688de35f" />


✔️ Event ID 8004

Go to: Computer Configuration > Policies > Windows Settings > Security Settings ->Local Policies -> Security Operation

<img width="1024" height="385" alt="image" src="https://github.com/user-attachments/assets/6eafdaae-c84f-49c1-b699-1c3965e2b5ba" />

Configure the following security policies:

Security policy setting	Value

🛡️ Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers	= Audit all

🛡️ Network security: Restrict NTLM: Audit NTLM authentication in this domain = 	Enable all

🛡️ Network security: Restrict NTLM: Audit Incoming NTLM Traffic =	Enable auditing for all accounts

Event ID 1644

Event ID 1644 is recommended for LDAP search events. Logging EventID 1644 can result in server performance impact. Important; the resource limitation part of the MDI sensor is not stopping the event collection. Make sure there are enough memory/ CPU and disk resources available.

<img width="1024" height="348" alt="image" src="https://github.com/user-attachments/assets/a174feaf-0ae2-4eb9-93bb-87b4b7425943" />

For Event 1644 is it needed to configure the following registry keys on the domain controllers:
[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics]
"15 Field Engineering"=dword:00000005

[HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS\Parameters]
"Expensive Search Results Threshold"=dword:00000001
"Inefficient Search Results Threshold"=dword:00000001
"Search Time Threshold (msecs)"=dword:00000001

Configure object auditing – 4662 events

For collecting 4662 events – it is needed to configure object auditing on the following objects:

- Descendant Group Objects
- Descendant User objects
- Descendant Computer Objects
- Descendant msDS-GroupManagedServiceAccount Objects
- Descendant msDS-ManagedServiceAccount Objects

Microsoft described the enablement for object auditing for all descendant objects. Use the Microsoft instructions for enabling the recommended set of permissions. 

Configure object auditing with reference to https://learn.microsoft.com/en-us/defender-for-identity/configure-windows-event-collection#configure-object-auditing

===========================================================================================

******Additional Permissions*****

Defender for Identity requires additional permissions for allowing remote calls to SAM and permissions to the selected object’s container in AD.

🛡️ Configure SAM-R

For lateral movement path detection, MDI relies on the SAM-R protocol configuration. The queries are performed with the SAM-R protocol.

Important: Apply the remote calls to SAM policy to all computers except domain controllers. The policy can break application that uses AuthZ interface. Source

It is needed to allow the Defender for Identity Directory service account for performing SAM-R. For configuring:

✔️ Go to: Computer Configuration > Policies > Windows Settings > Security Settings ->Local Policies -> Security Operation

✔️ Open the policy: Network access – Restrict clients allowed to make remote calls to SAM

- Allow the earlier created gMSA account
- Deploy the GPO to all computers except domain controllers
- Deleted Objects container permissions
  
gMSA account should have read-only permissions on the Deleted Objects container in AD. This allows Defender for Identity to detect user deletions from your Active Directory.

When not already enabled; enable the recycle bin feature and grant the MDI service account read and list permissions.

For enabling:

Enable-ADOptionalFeature -Identity 'Recycle Bin Feature' -Scope ForestOrConfigurationSet -Target (Get-ADDomain).DNSRoot -Confirm:$false
Adding permissions for the specific gmsaacountname:

dsacls "CN=Deleted Objects,$((Get-ADDomain).DistinguishedName)" /takeownership
dsacls "CN=Deleted Objects,$((Get-ADDomain).DistinguishedName)" /g "$((Get-ADDomain).NetBIOSName)\gmsaaccountname`$:LCRP"

=============================================================================================

***Capacity planning & hardware optimization***

NOTE: Run capacity planning before installing the Defender for Identity sensors and after configuring all events. The event set enables more load on the servers.

It is critical to enable enough capacity for Defender for Identity on the Domain Controllers. Microsoft released the Defender for Identity Sizing Tool for checking traffic information.

Run the TriSizingTool.exe for some time and check the results. The Busy Packets/sec value is needed. Map the actual Busy Packets/sec value with the Packets per second recommendation.


✔️ Download the Defender for Identity Sizing tool here https://aka.ms/mdi/sizingtool

✔️ Check the recommended sensor sizing here https://aka.ms/mdi/sizingtool

✔️ For 75-100k packages, the recommendation is 7.50 CPU/ Cores and 13.50 Memory/GB for only the sensor consumption.

🧠More information: Plan capacity for Microsoft Defender for Identity.


******Hardware*****

For healthy sensors, the following is recommended: https://learn.microsoft.com/en-us/defender-for-identity/capacity-planning#defender-for-identity-sensor-sizing

✔️ No hyper-threaded cores

✔️ Enable the Power Option to High Performance

✔️ When running the sensor as a virtual machine, it is recommended to assign all memory to the machine at all times. Memory ballooning or Dynamic Memory is not recommended and can result in health issues.

✔️ For Hyper-V ensure that Enable Dynamic Memory isn’t enabled for the VM. For VMware ensure that the amount of memory configured and the reserved memory is the same or configure – reserve all guest memory

More information: Server specifications https://learn.microsoft.com/en-us/defender-for-identity/prerequisites#server-specifications


*****IPv4 TSO offload*****

When using Defender for Identity on VMware virtual machines, sometimes the health alert “Some network traffic is not being analyzed” is visible. For resolving the issue in Vmware it is recommended to disable IPv4 TSO Offload.

Validate of LSO is enabled:

Get-NetAdapterAdvancedProperty | Where-Object DisplayName -Match "^Large*"

When the display value is reporting enabled for the Large Send offload it is recommended to disable LSO. (These actions might cause a brief loss of network connectivity and requires a reboot of the machine)

Disable LSO:

Disable-NetAdapterLso -Name {name of adapter}

==================================================================================================

****Network****

Defender for Identity requires some network requirements for portal connectivity and internal connectivity.

Important is correct connectivity for internal ports and localhost ports. Microsoft explains are required ports here; [Defender for Identity Ports | Microsoft Docs.](https://learn.microsoft.com/en-us/defender-for-identity/prerequisites#ports)

Network Name Resolution (NNR)
Network Name Resolution (NNR) is one of the main components and critical for Defender for Identity. NNR is needed for resolving IP addresses to computer names. The sensor looks up the IP address using the following methods part of the NNR:

- NTLM over RPC (TCP Port 135)
- NetBIOS (UDP port 137)
- RDP (TCP port 3389) – only the first packet of Client hello
- Queries the DNS server using reverse DNS lookup of the IP address (UDP 53)
- 
<img width="771" height="494" alt="image" src="https://github.com/user-attachments/assets/22606326-5739-48eb-b6a2-0d206dad9a74" />

The secondary DNS lookup of the IP address is only performed when there is no response from any of the primary methods or there is a conflict in the response received from two or more primary methods.

NNR data is crucial for detecting the following threats:

- Suspected identity theft (pass-the-ticket)
- Suspected DCSync attack (replication of directory services)
- Network mapping reconnaissance (DNS)

More information: What is Network Name Resolution? https://learn.microsoft.com/en-us/defender-for-identity/nnr-policy

------------------------------------------------------------------------------------------------

******Onboard Defender for Identity instance******

The Defender for Identity cloud service, available within the U.S., Europe, and Asia, runs on Azure infrastructure. To use the cloud services; go to security.microsoft.com -> Settings -> Identities or go to security.microsoft.com/settings/identities

When opening the identities section for the first time it will create the Defender for Identity instance.

- Create Directory account connection
- Go to Directory Sensor accounts
- Click Add Credentials
- Fill in the account name(gMSA account) and domain. Enable the checkbox; Group managed service account when using gMSA. For the domain, it is important to use the full FQDN of the domain where the gMSA account is located.

<img width="1024" height="282" alt="image" src="https://github.com/user-attachments/assets/400396a0-db5e-4f81-8a1c-6b03bb38de4b" />

More information: https://learn.microsoft.com/en-us/defender-for-identity/directory-service-accounts

Onboard Sensor
After connecting the Directory service account it is possible to onboard the first Sensor. Open the Sensors view and click on Add sensor. Download the installer package and copy the Access key.

Important: The access key is only needed during the sensor installation and can be regenerated without any impact. When completed the sensor onboarding – it is recommended to reset the access key by clicking “Regenerate key”

<img width="1024" height="259" alt="image" src="https://github.com/user-attachments/assets/8d6c1a7a-403c-4b4d-8341-1b2949e80d38" />

Now we can use the downloaded “Azure ATP Sensor setup.exe” for installing the sensor on the Domain Controller. MDI requires .NET Framework 4.7 or later. When there is no .NET Framework 4.7 installed it will be part of the installation which may require a reboot.

Defender for Identity requires the Npcap driver, for new installation Npcap is part of the installation.

Important to allow network communication from the domain controllers to the Defender for Identity service IPs.

<img width="1024" height="628" alt="image" src="https://github.com/user-attachments/assets/dcfa4198-f8e1-4413-8e98-ccc487cfafaa" />


<img width="1024" height="631" alt="image" src="https://github.com/user-attachments/assets/ce5a3c2a-628f-41c5-9b8a-5636f600772b" />


<img width="1024" height="621" alt="image" src="https://github.com/user-attachments/assets/df0fdc9d-b2a4-42f8-a7a4-ea6e72904156" />


<img width="1024" height="622" alt="image" src="https://github.com/user-attachments/assets/59957097-e43b-468e-8be3-a470e9019eec" />


<img width="1024" height="630" alt="image" src="https://github.com/user-attachments/assets/abe79256-0a32-494d-ac9a-da0eb4337d82" />


Check of the AATPSensor and AATPSensorUpdater services are running.

====================================================================================================================

Configure Defender for Identity sensor
After onboarding, the sensor is visible in the security.microsoft.com portal. Additional configuration is possible. For each sensor the following options are available:

✅ Enable delayed updated
✅ Configure additional network adapters
✅ Configure description


***Delayed update***

Defender for Identity releases rapidly new updates and features. When used in production it can be advised to configure a sort of deployment ring for the initial test and larger gradual update process. With the delayed update it is possible to delay the updates automatically.

<img width="1024" height="212" alt="image" src="https://github.com/user-attachments/assets/e2444fab-344b-498a-86c8-346e1608dde3" />

Sensors not selected for the delayed update are updated automatically. When enabled Delayed update there is a delay of 72 hours.

****Description****

Add optional a description for the Defender for Identity sensor:

<img width="1024" height="217" alt="image" src="https://github.com/user-attachments/assets/cc1e7f61-af83-4a9a-b35e-1c8af240af57" />


***Validate***

Validate MDI prerequisites :

With the use of the test-MDIReadiness.ps1 script it is possible to detect misconfigured environments. The script will check for Object Auditing, Exchange Auditing, ADFS Auditing, Advanced Audit Policy Configuration/ NTLM auditing/ Power scheme/ Root certificates. Part of the result is the JSON file and HTML file.

The script can be downloaded from GitHub https://github.com/microsoft/Microsoft-Defender-for-Identity/tree/main/Test-MdiReadiness

<img width="1024" height="367" alt="image" src="https://github.com/user-attachments/assets/a2d7ff65-2de5-4b20-a6c1-49047af9317f" />

****Validate sensor/ installation****

For validating Defender for Identity sensors check the following items:

✅ Check that the service; Azure Advanced Threat Protection sensor is correctly running.

✅ Validate in the portal of the Defender for Identity sensor is correctly reporting.

<img width="1024" height="381" alt="image" src="https://github.com/user-attachments/assets/5adefca5-e806-40a6-89ef-e3fb449d4f20" />

The following logs can be used for the Sensor validation. Default Location: C:\Program Files\Azure Advanced Threat Protection Sensor\version number\Logs

<img width="755" height="410" alt="image" src="https://github.com/user-attachments/assets/f9dca710-005f-4d4c-a637-726896aa72d5" />

***Validate data***

Validation of data is possible with the use of the security.microsoft.com portal. Use the search user or activity log (filtered for app Active Directory).

The old Defender for Identity portal; https://portal.atp.azure.com/ can be still used for checking devices and other events. Search for users/ computers or other objects:

<img width="1024" height="500" alt="image" src="https://github.com/user-attachments/assets/a6e533c8-7ebb-4abf-a06d-964c7c59aca6" />


****Health alerts****

Check the health alerts. After some time Defender for Identity reports possible health alerts based on the actual configuration. Examples of health alerts;

🔐 All domain controllers are unreachable by a sensor

🔐 All/Some of the capture network adapters on a sensor are not available

🔐 Directory services user credentials are incorrect

🔐 Low success rate of active name resolution

🔐 No traffic received from domain controller

🔐 Read-only user password to expire shortly

🔐 Read-only user password expired

🔐 Sensor outdated

🔐 Sensor reached a memory resource limit

🔐 Sensor service failed to start

🔐 Sensor stopped communicating

🔐 Some domain controllers are unreachable by a sensor

🔐 Some Windows events are not being analyzed

🔐 Some network traffic could not be analyzed

🔐 Some ETW events are not being analyzed

🔐 Sensor with Windows Server 2008 R2: Will be unsupported soon

🔐 Sensor with Windows Server 2008 R2: Unsupported

🔐Sensor has issues with packet capturing component


For viewing the health alerts go to: Security.Microsoft.com -> Settings -> Identities -> Health issues.


<img width="1024" height="222" alt="image" src="https://github.com/user-attachments/assets/a51772a7-2b5c-4663-b8ff-062ebc8fcb4e" />


Recommended is to configure the Health issues notification for receiving any new health alerts. Open Health issues notification for the configuration and add the recipient email.


<img width="1024" height="362" alt="image" src="https://github.com/user-attachments/assets/19289fd4-6d08-4fdf-9917-22c38be70be3" />


****MDI Learning period****

Defender for Identity requires a machine learning period. Important to give MDI some time for learning and detection of known behaviors and learning patterns.

MDI uses the following learning period timeframe in days:

<img width="747" height="640" alt="image" src="https://github.com/user-attachments/assets/172b1bb1-4f1b-4b4a-8a10-fb9bfd81578b" />

Network mapping reconnaissance (DNS)

Run the following command prompt on a workstation part of the domain:

🌐 nslookup 
🌐 server domain.local
🌐 ls -d domain.local
🌐 Result: Alert with the title; Network mapping reconnaissance (DNS)

User and IP address reconnaissance

Download netsess here http://netsess.exe%20msdemo-dc01.msdemo.local/ and run the following command prompt on a workstation part of the domain:

NetSess.exe domain.local

Result: Alert with the title; User and IP address reconnaissance (SMB)

<img width="1024" height="392" alt="image" src="https://github.com/user-attachments/assets/305a49bc-47c9-422c-9b8f-5d89cf22af49" />


User and group membership reconnaissance (SAMR)

Run the following command line on a workstation part of the domain:


<img width="1024" height="461" alt="image" src="https://github.com/user-attachments/assets/97aca948-4964-495a-b447-c5195bff76e4" />

net user /domain 
net group /domain
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain 
net group "Schema Admins" /domain
Result: Alert with the title; User and group membership reconnaissance (SAMR)

Malicious request of Data Protection API (DPAPI) master key

Run the following command line on a workstation part of the domain:


<img width="1024" height="348" alt="image" src="https://github.com/user-attachments/assets/e441e6ed-71bb-4e5f-a4c3-bfcd420c0f4d" />


mimikatz # privilege::debug

mimikatz # lsadump::backupkeys /system:m365securitylab.local /export 

Result: Alert with the title; Malicious request of Data Protection API (DPAPI) master key

<img width="1024" height="360" alt="image" src="https://github.com/user-attachments/assets/2800c62e-3f9d-4636-b9a4-053f381d2502" />

More attack simulations can be found here: [Attack simulations for Microsoft Defender for Identity
](https://learn.microsoft.com/en-us/defender-for-identity/playbooks)


View the available alert overview here: [Microsoft Defender for Identity Security Alerts](https://learn.microsoft.com/en-us/defender-for-identity/alerts-overview)

--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------

***Create Directory Service account (gMSA account)***

Defender for Identity supports two types of Directory Service accounts (gMSA and regular user account) – it is heavily advised to use the more secure Group Managed Service Account in the environment. With the use of gMSA DSA Active Directory manages the creation and rotation of the account password.

For more information and multi-forest environments see; [Microsoft Defender for Identity Directory Service account recommendations | Microsoft Docs](https://learn.microsoft.com/en-us/defender-for-identity/deploy/directory-service-accounts) 

***KDS root key***
It is needed to create a KDS root key. When the KDS root key is already available, no further action is required for the KDS root key. The KDS root key is used to generate passwords for AD Managed Service Accounts.

When there is no KDS root key; it is needed to wait 10 hours before creating the gMSA-account.

Validation of the root key is possible using the command: Get-KDSRootKey/ Get-KDSConfiguration. For creating the root key use the following PowerShell command:
Add-KdsRootKey -EffectiveImmediately 

More information: Create the Key Distribution Services KDS Root Key | [Microsoft Docs](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/create-the-key-distribution-services-kds-root-key)

***Create gMSA account***
For the gMSA account all domain controllers with the sensor must have managed password permission/right on the gMSA account. This can be created with a custom group/ single entries or default Domain Controller group. For allowing access the PrincipalsAllowedToRetrieveManagedPassword is needed which ensures that all Domain Controllers will be able to retrieve the password for the accounts.

The sensor with the name ( Azure Advanced Threat Protection Sensor) service runs as LocalService. Sometimes when the Log on as a service policy is configured – it is needed to add the gMSA account to the list of accounts that can log on as a service. NOTE: Only needed for Domain Controllers.

gMSA can be created with the following PowerShell command. Recommended is to use Kerberos encryption type AES256 and optionally -ManagedPasswordIntervalInDays parameter.

New-ADServiceAccount -Name MDIGMSA -DNSHostName contoso.m365securitylab.local –Description "Microsoft Defender for Identity service account" –KerberosEncryptionType AES256 –ManagedPasswordIntervalInDays 30

****Get gMSA details:****

Get-ADServiceAccount MDIGMSA -Properties * | fl DNSHostName, SamAccountName, KerberosEncryptionType, ManagedPasswordIntervalInDays, PrincipalsAllowedToRetrieveManagedPassword

Validation of the server has the required permission to retrieve the gMSA password can be validated using the following PowerShell command:

Test-ADServiceAccount -Identity 'contoso'

================================================================================================================================================================================================================

Step 2: Access the Defender Portal https://security.microsoft.com
- Go to the Microsoft Defender Portal and sign in with an account that has Security Administrator or Global Admin privileges, follow the marker (yellow) to add your on-premise server sensor as shown below.
<img width="1727" height="772" alt="image" src="https://github.com/user-attachments/assets/33d45799-2bbe-4825-a314-55bd4225b8ad" />

Step 3: Create the MDI Instance
- In the portal, navigate to Settings > Identities > Defender for Identity.

- Click Create instance and follow the wizard to:

- Name your instance
- Select the region
- Confirm Active Directory forest details

Step 4: Configure Directory Service Account
- Create a gMSA (Group Managed Service Account) for the sensor to authenticate with domain controllers.

Assign permissions:

- Read access to Deleted Objects container

- Remote SAM-R access for lateral movement detection

- Logon as a service rights on domain controllers

Step 5: Download and Install the Sensor
From the Defender portal, download the MDI Sensor installer.

Install it on each domain controller:

Use the gMSA credentials

Validate connectivity to Defender cloud service

Confirm sensor health post-installation

Step 6: Verify and Monitor
After installation, go to Settings > Sensors in the Defender portal.

Confirm sensors are active and reporting.

Use the Alerts, Timeline, and Investigation tabs to monitor identity threats.

🧠 Pro Tips for Enterprise Deployment
Run capacity planning before rollout to avoid performance bottlenecks.

Use Microsoft Entra ID Protection alongside MDI for cloud identity correlation.

Integrate with Microsoft Sentinel for advanced SIEM workflows.

For a full deployment guide, visit Microsoft’s official documentation. If you'd like help drafting a reproducible onboarding checklist or configuring alerts for CareSight’s infrastructure, I’d be happy to assist.
