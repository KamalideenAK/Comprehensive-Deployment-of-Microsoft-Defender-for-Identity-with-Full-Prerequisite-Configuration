# Microsoft-Defender-for-Identity-MDI-
Enabling Microsoft Defender for Identity (MDI) is a strategic move for protecting your hybrid Active Directory environment from identity-based threats. Here's a clear, step-by-step guide tailored for your enterprise-level expertise

🛡️ What Is Defender for Identity?
MDI is a cloud-based security solution that monitors on-premises Active Directory signals to detect suspicious activities, compromised identities, and lateral movement.

Microsoft Defender for Identity MDI (previously called Azure Advanced Threat Protection or Azure ATP) is a Microsoft security solution that captures signals from Domain Controllers. MDI is a cloud-based security solution that leverages on-premises Active Directory signals for detecting identity attacks.

Microsoft Defender for Identity works based on four security pillars:
🛡️ Prevent
🛡️ Detect
🛡️ Investigate
🛡️ Respond

Defender for Identity monitors the domain controllers by capturing and parsing network traffic and using the Windows events directly from the domain controllers. With the use of profiling, deterministic detection, machine learning, and behavioral algorithms Defender for Identity learns from the environment and enables the detection of anomalies.

Defender for identity security posture assessment can detect vulnerabilities such as,
• Exposing credentials in clear text
• Legacy protocols in use
• Unsecure Kerberos delegation
• Dormant accounts in sensitive groups
• Weaker cipher usage
• Print spooler service in Domain controllers
• Not managing local administrator accounts centrally (Microsoft LAPS)
• Lateral movement paths
• Unmonitored domain controllers
• Unsecure Account attributes
• Unsecure SID history attributes

Components
Defender for Identity consist of the following components:
🧠 Microsoft 365 Defender portal: MDI is integrated into the Microsoft 365 Defender portal
🧠 Defender for Identity sensor: Sensor is installed on Domain Controllers for monitoring all traffic
🧠 Defender for Identity cloud services: Separate environment hosted in Azure. MDI cloud service runs on Azure infra and is connected with the security graph.

Defender for Identity viewed from a simplified view. Image source: Microsoft

<img width="1024" height="409" alt="image" src="https://github.com/user-attachments/assets/4c30cce4-70c7-4127-b6fd-6e746012f806" />

The MDI Sensor contains a couple of core functionalities that are critical for getting MDI onboarded. The installed sensor is responsible for the following activity:

1) Capture and inspect domain controller network traffic (local traffic of the domain controller)
2) Receive Windows Events directly from the domain controllers
3) Receive RADIUS accounting information from your VPN provider
4) Retrieve data about users and computers from the Active Directory domain
5) Perform resolution of network entities (users, groups, and computers)
6) Transfer relevant data to the Defender for Identity cloud service

🚀 Step-by-Step: Enable Microsoft Defender for Identity

*****Preparation of the environment*****

Step 1: Prepare Your Environment

Licensing is user-based. Common mistake; purchase licenses based on the sensor count. Defender for Identity is user-based counted on the AzureAD users. The following licenses are available;
I) Enterprise Mobility + Security E5/A5
II) Microsoft 365 A5/ E5/ G5
III) Microsoft 365 A5/ E5/ G5/ F5 Security license.

- Ensure you're licensed with Microsoft 365 E5, Microsoft 365 E5 Security, or have purchased Defender for Identity as an add-on.

- Confirm your domain controllers run Windows Server 2016 or later.

- Enable Windows Event Forwarding and configure audit policies as per Microsoft’s recommendations here (https://learn.microsoft.com/en-us/defender-for-identity/deploy/deploy-defender-identity)

🚀 Network

- Sensors able to reach Defender for Identity Cloud service
- Specific ports allowed from Defender for Identity sensors in the environment
- Network Name Resolution requirements enabled

🚀Audit
Enable audit policies
Enable audit policies for Event ID 8004
Enable audit policies for Event ID 1644
Enable object auditing
Enabled optionally exchange auditing

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
