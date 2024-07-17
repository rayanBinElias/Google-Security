Udemy Set 1

1. Session Controls
    - defines how long users remains active 

  Reauthenticaiton Freq
    - reduce session exposure time
    - req users to confirm identity again

  Org Policy constraints
    - centralized mngmt of resources w/in scope o policy

2. Service account key
  - a bot that interacts across GC services to lessen user intervention

  Audit logs
    - records admin activties and access including API keys

  Logs Explorer
    - allows users to sort, search., and anlayze log dat across GC services

3. Org policy 
  - centralized cloud governance and compliance

  CMEK  
    - cryption keys that are created, owned, and managed by customers, giving them control over the encryption and decryption of their data at rest in Google Clou

  constraints
    - limit control of resources

  policy binding
    - enforce define restrictions across resources

  deny policies
    -

4. Google Cloud Directory Sync: A tool used for synchronizing data from Active Directory or LDAP servers to Google Cloud Identity or G Suite accounts, typically for user and group management.

LDAP search rules: Search rules defined within an LDAP system to filter and retrieve specific records based on the defined attributes or conditions from a directory service.

One-way synchronization: A data sync process where information is transferred from one source (e.g., Active Directory) to another (e.g., Cloud IAM) but not in the reverse direction, thus only updating the target system.

5.SAML Federation: Security Assertion Markup Language (SAML) Federation is a standard for exchanging authentication and authorization data between parties, particularly between an identity provider and a service provider.

2-Step Verification: 2-Step Verification provides an additional layer of security by requiring a second form of verification in addition to the password.

Security Keys: Physical devices used to provide two-factor authentication for a user account, considered more secure than verification codes sent via SMS.

LDAP: Lightweight Directory Access Protocol (LDAP) is a protocol designed to manage and access distributed directory information services over an Internet Protocol network.

Post-SSO: Refers to the authentication steps that take place after Single Sign-On (SSO) has been used to log into an application or service.


6.Packet Mirroring: Packet Mirroring is a feature that copies network traffic from specified instances inside a Virtual Private Cloud (VPC) and forwards it to a monitoring collector for analysis, aiding in network and security forensics.

Encrypted Traffic Analysis: Encrypted Traffic Analysis involves inspecting the patterns and metadata of encrypted data packets to detect potential threats or compliance issues without decrypting the traffic.

Load Balancers: Load balancers distribute network or application traffic across multiple servers to ensure availability and reliability of services by minimizing the load on individual servers.

Compliance Monitoring: Compliance Monitoring refers to the process of systematically tracking and managing compliance with legal, regulatory, and policy requirements, particularly in data management and protection.
7.Confidential VMs: Virtual machines that encrypt data in use with memory encryption, ensuring that data being processed is protected, even from privileged access at the hypervisor level.

Anthos Service Mesh: A service management layer that provides end-to-end encryption for data in motion, securing communications between services in a cloud-native application.

Application-layer encryption: The process of encrypting data within the application before it is stored or transmitted, giving developers granular control over data security and compliance.
8.HIPAA Compliance: Refers to the set of standards established to protect sensitive patient health information from being disclosed without the patient's consent or knowledge.

Data Egress: The flow of data outward from a network, typically when transferring from internal storage to an external destination.

Egress Controls: Security measures implemented to monitor and potentially restrict the flow of information exiting a network boundary.

9.Automated scan cycles: The process of executing security scans automatically at regular intervals, without manual initiation, to identify vulnerabilities.

Cross-scripting security flaws: Also known as XSS attacks, these are security vulnerabilities that allow attackers to inject malicious scripts into web pages viewed by other users.

Authentication using Google accounts: The capability of a security system to use Google account credentials for verifying the identity of users attempting to gain access.

10.Google Cloud Directory Sync: A service enabling administrators to synchronize and manage user and group details from the LDAP directory service to Google Cloud Directory.

LDAP Group Membership: Refers to the assignment of users to certain groups within an LDAP directory, typically used for granting access rights and permissions in a hierarchical approach.

IAM Policies: Set of rules defined in Google Cloud IAM that governs the permissions for resources - what can be done by whom. They can be applied on the organizational, folder, project, or resource level.
11.Reflected JSON Injection: An attack technique where unsanitized user input is interpolated into JSON responses, potentially allowing attackers to manipulate API responses or execute malicious scripts on client browsers.

Web Security Scanner: A tool that automatically scans and detects security vulnerabilities in web applications hosted on Google Cloud, and is part of the Google Cloud Security Command Center.

JSON Serialization Library: A software component that converts objects into a JSON format, with some libraries providing default output encoding to sanitize content and prevent injection attacks.
12.Resource Location Restriction: A feature within Organization Policy Service that enables control over where resources can be created by defining resource locations at the organization level.

Organization Policy Service: A service in Google Cloud that offers central, programmatic control over an organization's cloud resources, allowing admins to set constraints across the entire resource hierarchy.

Data Sovereignty: The concept that digital data is subject to the laws and governance structures within the nation it is located or stored.
13.Phishing-resistant 2FA: Authentication method designed to resist phishing attacks. It typically involves hardware tokens that can verify the legitimacy of the website a user is logging into.

Cryptographic Token: A hardware device used for securing account access by generating encrypted authentication codes that can validate user identity.

U2F (Universal 2nd Factor): An open authentication standard that strengthens and simplifies two-factor authentication using specialized USB or NFC devices.
14.VPC Service Controls: A security feature that allows enterprises to set up a secure perimeter around Google Cloud resources to mitigate data exfiltration risks.

Organization Node: The root node in the Google Cloud resource hierarchy that represents an organization and manages policies including IAM and resource constraints at a global level.

IAM Policies: Defines who (identity) has what access (roles) to a particular Google Cloud resource. It is crucial for security and proper access management.

15.Google Workspace Admin Console: An administrative interface that allows the management of Google Workspace services, such as managing user accounts, groups, organizational units, and security settings related to Google Workspace applications.

16.Service Account Key: Service account keys are used for server-to-server interactions that involve a service account, like automated services running on virtual machines.

Audit Logs: Audit logs record administrative activities and accesses within your cloud environment, which are crucial for security and compliance monitoring.

Logs Explorer: A feature within Google Cloud's operations suite that allows users to search, sort, and analyze log data across Google Cloud services.

17.Principle of Least Privilege: A security concept where a user is given the minimum levels of access – or permissions – needed to perform his/her job functions.

Service Account: Service accounts are a type of Google account that represent a non-human user that applications or services can use to interact with Google Cloud resources.

Metadata Server: A service provided by Google Cloud to VM instances, allowing them to retrieve instance-specific data like service account credentials without having to pre-embed secrets.

18.Global HTTPS Load Balancer: A component that balances HTTP and HTTPS traffic across multiple Compute Engine regions, improving performance and reliability.

Google Cloud Armor: A security service that provides DDoS defense and application-level traffic control for resources behind the external HTTP(S) Load Balancer.

Throttle Action: An adaptive protection feature of Google Cloud Armor that limits the request rate from an IP or range to a target service.

Rate-based Ban: An automatic action within Google Cloud Armor triggered when a threshold request rate is exceeded, banning further requests for a set duration.

19.Organization Policy: A policy resource that defines restrictions on how resources can behave in the Google Cloud resource hierarchy. It's fundamental for cloud governance and compliance.

Customer-Managed Encryption Keys (CMEK): Encryption keys that are created, owned, and managed by customers, giving them control over the encryption and decryption of their data at rest in Google Cloud.

Constraints: The specific aspects or behaviors of resources that can be limited or controlled within an organization policy to adhere to company guidelines or compliance requirements.

Policy Binding: Associates the policy with specific resources, such as projects, folders, or the organization, to enforce the defined restrictions where applicable.

Deny Policies: A type of organization policy that lets administrators specify a list of services or actions that are not allowed within the scope of the policy.

Resource Labels: Key-value pairs used to organize Google Cloud resources into groups that reflect organizational structures and allow for easier management and filtering.

20.Owner roles: Owner roles on a GCP resource grant a wide array of permissions, including managerial control over the resource and the ability to set access policies.

Domain restricted sharing: This policy setting within the GCP's Resource Manager prevents resources from being shared with identities outside of the trusted organization domain.

Organization policy: An organizational policy is a configuration of restrictions that provides centralized control over GCP resources for a GCP organization.

21.Event Threat Detection: This fully managed service helps detect threats within the cloud logs automatically. It identifies unusual and potentially harmful activity, such as the deployment of malicious software or abusive behavior.

Security Health Analytics: This automated security assessment service provides visibility into potential vulnerabilities and threats in your Google Cloud resources, offering recommendations for improving security posture.

22.Shared VPC: Allows an organization to connect resources from multiple projects to a common VPC network, enabling communication between them while keeping resource management centralized.

Compute Network User role: Provides permissions to create, modify, and use network resources, but does not permit management of the resources.

Role granularity: Defines the specificity level of permissions assignment in Google Cloud, which can be set at the organization, folder, project, or resource level.

23.Object Lifecycle Management: A feature in Cloud Storage allowing users to automatically manage the lifecycle of objects based on specified conditions, like age, which helps in adhering to compliance regulations.

24. Egress Firewall Rule: This is a network security policy that controls the outbound traffic from your network to the internet or other networks, based on defined rules regarding the destination addresses, ports, and protocols.

Priority (Firewall Rules): In firewall settings, priority determines the order in which rules are evaluated. Lower numeric values indicate higher precedence. Rules with the lowest priority number are evaluated first.

25.Identity-Aware Proxy (IAP): An integrated service that enhances application security by allowing fine-grained access control. IAP verifies user identities and the context of their requests to determine if they should access an application.

IAP-secured Tunnel User role: A predefined Identity and Access Management (IAM) role in Google Cloud that grants permissions to create secure tunnels to IAP-secured resources, suitable for administrators who need remote access.

Firewall rule for IAP IP scope: A security policy that allows network traffic from IAP's forwarding IP ranges. It ensures only IAP-authenticated users can initiate sessions, enhancing connection security.

26.Admin Activity audit logs: Logs that record operations that modify the configuration or metadata of resources. Essential for monitoring and securing administrative actions.

Data Access audit logs: Logs that track API calls that create, modify, or read user-provided data. Vital for assessing who accesses sensitive data and how.

System Event audit logs: Logs that record Google Cloud system events, which are automatically produced by Google services, rather than driven by direct user actions.

Cloud Load Balancing logs: Logs generated by Google Cloud Load Balancing, providing insights into the requests made to an application rather than access to the configuration data.

Compute Engine operation logs: Logs that detail operations performed on Compute Engine resources, relevant to infrastructure activities but not directly to sensitive data access.

27. Organizational Node: The root-level container for all resources in a Google Cloud hierarchy. It provides centralized control over resource inheritance, policy setting, and IAM role assignments.

Folders: Hierarchical elements within Google Cloud that allow the grouping of related projects and other folders. Folders facilitate finer-grained access control and organization of cloud resources based on team, department, or other categorizations.

IAM Permissions: The mechanism within Google Cloud IAM that controls access to resources by defining who (identity) has what access (role) for which resource.

28.Admin Activity audit logs: Logs that record operations that modify the configuration or metadata of resources. Essential for monitoring and securing administrative actions.

  Data Access audit logs: Logs that track API calls that create, modify, or read user-provided data. Vital for assessing who accesses sensitive data and how.

  System Event audit logs: Logs that record Google Cloud system events, which are automatically produced by Google services, rather than driven by direct user actions.

  Cloud Load Balancing logs: Logs generated by Google Cloud Load Balancing, providing insights into the requests made to an application rather than access to the configuration data.

  Compute Engine operation logs: Logs that detail operations performed on Compute Engine resources, relevant to infrastructure activities but not directly to sensitive data access.

29. Symmetric Encryption: A type of encryption where the same key is used for encrypting and decrypting data. It is essential for performance when encrypting data at rest.

Data Encryption Key (DEK): A key used to directly encrypt data, this is often encrypted with another key (a KEK) for additional security layers and key management convenience.

Key Encryption Key (KEK): A key that is used to encrypt, or wrap, other keys (such as DEKs) to enhance the security of key management processes.

Cloud Key Management Service (KMS): A cloud-based service that allows users to manage cryptographic keys for their cloud services in a secure and compliant way.

30. HIPAA compliance: Regulatory standards imposed by the Health Insurance Portability and Accountability Act (HIPAA), which set the standard for sensitive patient data protection.

PHI data environment: A specialized computing environment that stores, processes, or handles Personal Health Information (PHI), which requires stringent security and compliance controls.

Google Cloud project segregation: The practice of using separate Google Cloud projects to isolate resources and control access. This can reduce the complexity and scope of compliance and security efforts.

31. Data Residency: Data residency refers to the physical or geographical location where data is stored. Certain regulations and corporate policies may dictate that data is stored within specific regions to meet compliance requirements.

Retention Policy: A retention policy is a set of rules that governs how long data should be preserved before it can be deleted. Compliance with legal and regulatory requirements often dictates these policies.

Economically Viable: When a solution is economically viable, it means it is cost-effective and does not impose undue financial burden over the time it is in use, considering both initial and ongoing expenses.

32. Dedicated Interconnect: Provides a direct physical connection between an organization's network and Google's network, offering highly available and low latency connections.

Cloud Router: Works with VPNs to dynamically exchange routes between your Google Cloud VPC and on-premises networks by using Border Gateway Protocol (BGP).

Cloud VPN: Establishes a secure and encrypted connection over the public internet between an on-premises network and your Google Cloud VPC.

Partner Interconnect: Offers connectivity to Google Cloud through a supported service provider, suitable for organizations requiring less capacity than Dedicated Interconnect.

33. DNS Security Extensions: DNSSEC is an advanced security feature that adds a layer of authentication to the DNS resolution process, using digital signatures to ensure that the received DNS responses are authentic and have not been tampered with.

34. Cloud Identity: A Google Cloud service for managing users, groups, and domains in a unified way across all Google Workspace services without the need for a dedicated on-premises directory server.

Google Cloud Directory Sync (GCDS): A tool that synchronizes user data from an Active Directory or LDAP server with Google Cloud Identity accounts to streamline the management of Google services in an enterprise environment.

Unmanaged Account: An account created outside of a company's domain control, often by an individual signing up for Google services with a work email before these services are officially provided by the company.

Admin SDK: A set of APIs that allows developers to perform administrative tasks in G Suite such as managing users, apps, and devices, often used in conjunction with Directory API for User management.

35. Shared VPC: Allows resources from multiple projects to connect to a common Virtual Private Cloud for centralized management, contributing to a more organized and secure network.

Host project: A component of Shared VPC that holds the shared network resources and is responsible for their management, while other projects, known as service projects, use these resources.

Service projects: In a Shared VPC setup, these are the individual projects that connect to the host project's network resources, enabling resource sharing and centralized control.

Dedicated private connection: Refers to solutions like Cloud Interconnect, which provide a direct, private network connection between on-premises networks and Google Cloud.

36.Google Cloud Directory Sync: A tool used for synchronizing data from Active Directory or LDAP servers to Google Cloud Identity or G Suite accounts, typically for user and group management.

LDAP search rules: Search rules defined within an LDAP system to filter and retrieve specific records based on the defined attributes or conditions from a directory service.

One-way synchronization: A data sync process where information is transferred from one source (e.g., Active Directory) to another (e.g., Cloud IAM) but not in the reverse direction, thus only updating the target system.

37.Least Privilege Principle: A security concept that recommends giving a user account only those privileges which are essential to perform its intended function.

IAM Role: Defines a set of permissions to perform specific actions on Google Cloud resources that can be assigned to users, groups, or service accounts.

Organization Policy: The configuration of governance rules for an entire organization that guides the deployment and usage of Google Cloud resources.

Billing Account: An account linked to a Google Cloud project that defines who pays for the resources and Google Cloud services used by that project.

38.Cloud Data Loss Prevention (DLP): Google Cloud service designed to detect and classify sensitive data, supporting automated and fine-grained control over how data is managed and ensuring compliance with data protection regulations.

Cloud Functions: An event-driven, serverless compute platform provided by Google Cloud that allows developers to run backend code in response to events triggered by Google Cloud services or HTTP requests.

Pub/Sub: A real-time messaging service that enables applications to exchange messages reliably, securely, and asynchronously. Key when integrating applications and services in an event-driven architecture.

39.VPC Service Controls: A security layer for Google Cloud resources that allows you to define a security perimeter around data stored in GCP services to limit data exfiltration risks.

Access Level: Part of VPC Service Controls, Access Levels allow the configuration of attributes such as IP address ranges to enforce fine-grained access control to GCP resources.

40.Session Duration: The amount of time a session remains active without requiring re-authentication. Adjusting session duration can forcefully log users out after periods of inactivity, enhancing security.

Google Workspace Enterprise Edition: A premium offering from Google that provides advanced features for businesses including enterprise-grade access and identity management solutions.

41.Identity-Aware Proxy (IAP): A service that controls access to cloud applications running on Google Cloud by verifying a user's identity and determining if that user should be allowed to access the application.

Least Privilege: A security principle advocating that users and systems are granted the minimum levels of access – or permissions – needed to perform their tasks.

SIEM: Security Information and Event Management tools provide real-time analysis of security alerts and events across an organization's IT infrastructure.

Data Access audit logs: Records that track accesses to user-made content by Google Cloud services. Useful for auditing access patterns and understanding security incidents.

42.Session Control: A feature in Google Cloud that defines how long a user session remains active. It can force reauthentication and terminate sessions based on configured time intervals.

Reauthentication Frequency: A security setting that requires users to confirm their identity again after a specified period. It is used to enhance security by reducing the session's exposure time to hijacking threats.

Organization Policy Constraints: These constraints provide centralized governance over resources by enforcing specific requirements across all projects and services within the scope of the policy.

43. Crypto-shredding: A security practice where encryption keys are destroyed to render associated data unreadable, effectively 'shredding' the data without deleting the actual data files.

Cloud Key Management Service (KMS): A cloud service that manages encryption keys, enabling centralized control over cryptographic operations and the secure deletion of keys.

44. Organization Policy: A set of constraints that provides centralized control over your organization's cloud resources, hence ensuring that specific requirements like security configurations are uniformly applied.

Machine Image: A complete snapshot of a virtual machine's disk and metadata definition, encapsulating all necessary information to replicate the VM in a consistent state.

Boot Disk: The primary disk that contains the operating system and boot-up scripts for a virtual machine. Control over boot disk creation can enforce security compliance.

45. Deterministic encryption: A form of encryption that produces the same encrypted text for a given piece of data each time. Especially useful in scenarios where encrypted data needs to match across different systems.

AES-SIV: Authenticated encryption mode that allows encryption to be deterministic, which means the same plaintext encrypted with the same key always produces the same ciphertext.

Data anonymization: The process of protecting private or sensitive information by erasing or encrypting identifiers that connect an individual to stored data.

46. Data Access logs: Detailed audit logs within Google Cloud that record when data is created, modified, or accessed. Useful for forensic and compliance purposes, especially regarding unauthorized access investigations.

API calls: Requests made to API endpoints that execute operations, such as accessing, modifying, or managing resources within Google Cloud services.

47. Google Cloud Directory Sync: A service that synchronizes user accounts from an existing Active Directory or LDAP server with Google Cloud identity services, enabling centralized user management.

SSO (Single Sign-On): An authentication process that allows users to access multiple applications with one set of login credentials, improving user experience and security.

Active Directory (AD): A directory service developed by Microsoft for Windows domain networks. It is widely used for user and identity management.

LDAP (Lightweight Directory Access Protocol): An open, vendor-neutral application protocol for accessing and maintaining distributed directory information services over an internet protocol network.

Kerberos: A network authentication protocol designed to provide strong authentication for client/server applications by using secret-key cryptography.

48. Shielded VMs: A service offering from Google Cloud that provides fortified virtual machines with features like secure boot, vTPM, and integrity monitoring to protect against rootkits and bootkits.

Confidential VMs: A breakthrough technology provided by Google Cloud that encrypts data in-use with a hardware-rooted solution, ensuring the data remains opaque to the infrastructure handling it.

Secure Boot: A security feature that prevents unauthorized software from booting on a system by verifying digital signatures of the boot components against known good signatures.

vTPM: Virtual Trusted Platform Module acts as a secure cryptoprocessor that enhances hardware security by facilitating secure generation of cryptographic keys.

Integrity Monitoring: A security capability that checks and reports the integrity of the systems to detect if they have been tampered with, especially useful against root-level compromises.

49. Symmetric encryption: This type of encryption uses a single key for both the encryption and decryption processes. It is efficient for bulk data encryption but poses a risk if the key is compromised.

Key version rotation: The process of creating a new version of the encryption key while keeping the old versions available. Regular rotation can limit the amount of data exposed in the event of a key compromise.

Transactional data: Data that records the transactions of a business or any data-exchange entity. Ensuring its integrity and confidentiality is crucial to the entity's security posture.

50. External Key Manager (EKM): A security feature that allows you to use encryption keys managed outside of Google's infrastructure for data at rest in Google Cloud services, enhancing control over key management processes.

Hardware Security Module (HSM): A physical computing device that safeguards and manages digital keys for strong authentication and provides cryptoprocessing, which can operate both on-premises or in the cloud.

Key Access Justifications (KAJ): A feature of Google Cloud's External Key Manager that requires explicit justification for every access request to use the key, providing detailed access tracking and increased control over key usage.

Customer-supplied Encryption Keys (CSEK): Encryption model in Google Cloud where the customer provides their own encryption keys, directly managing and maintaining control of their own keys, not within a managed service.


Set 2
1. Policy Analyzer
  - Part of Google's Cloud IAM suite, 
  - Policy Analyzer enables the creation of reports and 
  - analysis of access policies across the cloud resources, 
  -which is integral to maintaining compliance and audit-readiness.

Audit Logs
  - Logs that record administrative activities and 
  - accesses within cloud environments. 
  - They are used for analysis in security investigations and compliance auditing.

2. Deterministic Encryption
  - A method of encryption where a given input always results in the same encrypted output. This property enables encrypted data matching across different datasets without revealing the original data.

De-identification
  - The process of removing or encrypting personally identifiable information from datasets, so that the privacy of the individuals in the dataset is protected.

Cloud Data Loss Prevention (DLP)
  - A Google Cloud service that provides data inspection, classification, and de-identification capabilities to help protect sensitive information and maintain compliance.

3. CIS Benchmarks
  - A set of best practice security configuration guides designed to provide prescriptive guidance for establishing a secure baseline configuration.

Security Command Center
  - Google Cloud's comprehensive security and risk management platform that provides unified visibility, continuous monitoring, and actionable security insights.

Mute Findings
  - A feature in Security Command Center allowing users to omit certain findings from view and reports, effectively ignoring them in security assessments.

Custom Rule
  - A user-defined criterion within Security Command Center that can automatically influence the interpretation or action taken on specific findings.

4.Multifactor Authentication
  - An authentication method requiring two or more verification factors to gain access to a resource, which dramatically increases account security by adding an additional layer of defense beyond just passwords.

5.Cloud VPN
  - Cloud VPN allows for the creation of a secure and encrypted connection over the internet between your Google Cloud network and your on-premises network.

Cloud Interconnect
  - Cloud Interconnect provides a higher-speed, more reliable, and lower-latency connection to Google Cloud than what internet-based connections can offer.

6. SAML
  - Security Assertion Markup Language (SAML) is an XML-based standard for exchanging authentication and authorization data between parties, particularly between an identity provider and a service provider.

SSO
  - Single Sign-On (SSO) is an authentication process that allows a user to access multiple applications with one set of login credentials, improving security and user experience.

gcloud CLI
  - The Google Cloud command-line interface (gcloud CLI) is a tool that provides the capability to manage Google Cloud resources and services via terminal commands.

7. Organizational Policy
  - A set of constraints that regulate the actions available across all Google Cloud resources within an organization. Used to enforce security rules and standards.

Service Account Keys
  - Authentication credentials used to access Google Cloud services programmatically. They pose a security risk if not managed properly.

8. Artifact Registry
  - A service for storing, managing, and securing Docker container images as well as other types of language packages. It is integrated with GKE and offers automated scanning features for vulnerabilities.

Cloud Build
  - A service that imports your source code, executes build instructions, and produces Docker images or other artifacts. It is often configured for continuous integration and continuous deployment workflows.

Vulnerability Scanning
  - The process of identifying and reporting security issues within software components. In the context of cloud services, it incorporates automated tools to scan container images for known vulnerabilities.

9. Retention Policy
  - A feature in Google Cloud Storage that allows you to set a minimum storage period for objects within a bucket, ensuring data cannot be deleted before the specified duration.

Object Versioning
  - A functionality in GCS that keeps a history of versions of an object within a bucket, protecting against accidental deletion and overwrites.

Bucket Lock
  - A tool in GCS that permanently enforces retention policies, preventing policy removal or alteration even by users with administrative permissions.

10. Cloud Data Loss Prevention (DLP)
  - A service that helps to manage and protect sensitive data by providing data inspection, classification, and redaction capabilities across Google Cloud services.

Redaction
  - The process of removing sensitive information from a document. In the context of data security, redaction obscures or eliminates personal or confidential information that should not be disclosed.

Preservation
  - In compliance contexts, preservation refers to the maintenance of data integrity and accessibility, often for legally mandated periods, without alteration or loss.

11.Cloud Data Loss Prevention (DLP): A service that helps to manage and protect sensitive data by providing data inspection, classification, and redaction capabilities across Google Cloud services.

Redaction: The process of removing sensitive information from a document. In the context of data security, redaction obscures or eliminates personal or confidential information that should not be disclosed.

Preservation: In compliance contexts, preservation refers to the maintenance of data integrity and accessibility, often for legally mandated periods, without alteration or loss.
12.Uniform bucket-level access: A feature in Cloud Storage that simplifies permission management by disabling object-level access and using only IAM policies for access control.

Cloud Audit Logs: Records events for auditing and compliance within Google Cloud services, which can help monitor who did what, where, and when.

IAM policies: Used to manage permissions for Google Cloud resources, allowing for precise control over who has what level of access.

13.Cloud Identity: A Google Cloud service that provides identity and access management, which helps ensure that the right users have the right access to resources.

SSO/SAML: Single Sign-On (SSO) using Security Assertion Markup Language (SAML) allows for a centralized authentication process across multiple web applications, enabling users to log in once and gain access to all associated services securely.

Predefined Roles: Roles within Google Cloud that are designed to provide granular permissions tailored to specific services and resources, promoting the principle of least privilege.
14.CI/CD: Continuous Integration and Continuous Deployment are DevOps methodologies designed to automate the process of software delivery. They enable frequent and reliable code changes to be made and deployed to production.

Custom Images: Custom images are bootable disk images that have been customized by adding or modifying files or settings and can be used to create new VMs or as the basis for a group of VMs in the cloud.

Phased Approach: A method of deploying updates or changes in stages. It reduces the risk by ensuring that not all systems are updated simultaneously, providing a rollback point if problems are encountered.
15.Custom Service Account: Custom service accounts are user-defined accounts that grant specific privileges to an application, allowing more granular control over the actions and resources a service can access.

constraints/iam.disableServiceAccountKeyCreation: This organizational policy ensures that service account keys cannot be created, adding an additional layer of security by preventing the potential misuse of long-lived credentials.
16.SSL Certificate: An SSL certificate is a digital certificate used to provide authentication for a website and enable an encrypted connection. This is crucial for securing data in transit.

HTTP(S) Load Balancer: An HTTP(S) Load Balancer distributes incoming HTTP or HTTPS traffic across multiple targets, such as virtual instances. It provides SSL termination, helping secure and manage data transfers.

Encryption: Encryption is the process of encoding data to prevent unauthorized access. It's essential for protecting sensitive information during transmission.
17.Folder: In Google Cloud, a Folder is an organizing entity that groups projects under an organization. Folders can be used to create a hierarchical structure for more granular access control and resource organization.

Google Group: A collection of users with a common set of permissions. Google Groups simplify permissions management by allowing a role to be assigned to all members of the group simultaneously.

Project Viewer role: Project Viewer is a predefined IAM role in Google Cloud that grants read-only access to view resources within a project, but does not allow the user to modify any resource or data.

Resource hierarchy: The structured organization of resources in Google Cloud, consisting of the Organization, Folders, Projects, and Resources, used to manage access control and project settings at scale.
18.VPC Peering: Allows private network traffic to flow between Virtual Private Clouds (VPCs) in different projects or organizations without traversing the public internet, using Google's internal network.

Data Layer: Typically refers to the database or storage tier within a multi-tiered architecture where data is stored and managed.

Processing Layer: A logical partition in a data processing architecture where the data is analyzed, processed, or transformed.

Health Data Compliance: Refers to adherence to laws and regulations, such as HIPAA, that govern the storage, processing, and transmission of healthcare-related data.
19.De-identification: The process of removing or altering information that identifies an individual, making it impossible or impractically difficult to link the data with the individual.

Tokenization: In this context, tokenization refers to the replacement of sensitive data elements with non-sensitive equivalents, known as tokens, which have no exploitable meaning or value.

HIPAA: Stands for Health Insurance Portability and Accountability Act, which sets the standard for protecting sensitive patient data in the US.
20.SLSA: Supply Chain Levels for Software Artifacts (SLSA) is a security framework aimed at ensuring the integrity of software artifacts throughout the software supply chain. It's a set of incrementally adoptable security guidelines.

Cloud Build: Cloud Build is a service that executes your builds on Google Cloud's infrastructure. It can import source code, execute build to your specifications, and produce artifacts such as containers or non-container artifacts.

Build Provenance: Build provenance is metadata that provides a verifiable record of the build process for a software artifact. It includes details such as which builder made the artifact, when and where.

Security Command Center: The Security Command Center is a security and risk management tool in Google Cloud that provides visibility into cloud assets, scans for vulnerabilities, and helps maintain compliance.
21.Format-Preserving Encryption: This encryption method encrypts data while maintaining the original data format, ensuring that encrypted data can be used in applications without modification.

Cryptographic Hashing: A process that converts data into a fixed-size string of characters, which is typically used for ensuring data integrity and is one-way and not reversible.

Redaction: The removal of sensitive information from a document or any medium, which results in permanent deletion of the specified data.

Generalization: In the context of data privacy, it is a method of de-identification that replaces detailed data with broader categories to protect sensitive information.
22.Least Privilege Principle: A security concept that advises giving users only the permissions that are essential for the performance of their duties, minimizing risk.

Role-Based Access Control (RBAC): A method of restricting system access to authorized users based on defined roles within an organization, combining permissions into roles.

Billing Account Viewer: An IAM role that allows users to view billing account cost information and transaction histories, without the ability to manage the billing setup.

Billing Account Costs Manager: An IAM role that grants privileges to manage budgets, alerts, and export billing data without broader account administration powers.
23.Dry Run Mode: A feature in VPC Service Controls that allows administrators to validate new access policies by simulating their effects before enforcement, identifying potential access issues with no impact on users or operations.

VPC Service Controls: A security feature that offers a perimeter to guard against data exfiltration from Google Cloud services, by managing communication between resources and services within the VPC.

Promote: An action to change the state of a configuration from a test or provisional status to active enforcement within a production environment.


24.Network Service Tier: A network service tier in Google Cloud defines the quality of the network in terms of performance and cost. The Basic tier is cost-effective, while the Premium tier provides higher performance.

Originating Client IP Preservation: In the context of load balancing, preserving the originating client IP address allows the destination server to see the actual IP address from which a request is initiated, offering benefits for security and analytics.


25.Cron Job: A cron job is a time-based scheduler in Unix-like operating systems. For Google Cloud, it's often used to automate the execution of tasks such as scripts or commands at specified times or intervals.

Gsutil: Gsutil is a Python application that lets users manage resources within Google Cloud Storage. It is used for a wide range of bucket and object management tasks, which includes transferring data to and from Cloud Storage.

Data Archival: Data archival refers to the process of moving data that is no longer actively used to a dedicated storage service for long-term retention. Archival solutions prioritize cost efficiency and data durability over immediate access or high throughput.

Business Continuity: Business continuity involves strategies and solutions that enable essential business functions to continue during and after serious incidents or disasters, such as maintaining or quickly resuming critical operations.

Economically Viable: This term refers to a solution that offers cost-effectiveness without compromising on required features or scalability, aligning with the firm's financial objectives and resource constraints.
26.Cloud Data Loss Prevention API: A service that helps you manage sensitive data. It provides classification, de-identification, and re-identification capabilities to help ensure data privacy and regulatory compliance.
27.term: Network Tags

description: Labels assigned to VM instances that work in conjunction with VPC firewall rules to control the flow of traffic between instances.

term: VPC Firewall Rules

description: Controls traffic to and from instances within Google Cloud VPCs. They are stateful and evaluated by their priority and target tags.

term: Firewall Priority

description: A numerical value associated with each VPC firewall rule that determines its evaluation order, with lower numbers signifying higher priority.
28.Container Isolation: A security principle where each container runs a single application or process, preventing issues in one container from affecting others and limiting the attack surface.

Minimalist Container Images: The practice of including only the necessary components within a container to run the specific application, which reduces the risk of vulnerabilities and potential exploits.
29.Organization Policy Constraint: An Organization Policy Constraint allows enterprises to configure policies that apply across resources in a GCP environment, adding a layer of governance to manage compliance and security settings.

Binary Authorization: Binary Authorization is a security control that ensures only trusted container images are deployed on GKE by requiring images to meet certain criteria and be signed off by authorities before use.

Attestations: Attestations are pieces of metadata associated with container images that are used to assert certain properties or approvals for the image, which in Binary Authorization, help determine whether an image can be deployed.
30.GCDS: Google Cloud Directory Sync is a tool that enables admins to synchronize user and group details with Cloud Identity or Google Workspace from a Microsoft Active Directory or an LDAP directory.

LDAP: The Lightweight Directory Access Protocol is an industry standard protocol used to access and manage directory information over a network, such as user accounts and groups, which Active Directory uses.

Cloud Identity: A service by Google that offers identity management and device administration capabilities, facilitating user access to applications and services with a single set of credentials.
31.Lift & Shift: A migration strategy that involves moving an application from one environment to another without redesigning the app. Often used to move legacy systems to the cloud.

VPC Firewall: A distributed, stateful firewall service for Virtual Private Clouds that provides network security control over types of traffic entering or exiting the network boundaries.

VPC Flow Logs: Records a sample of network flows sent from and received by VM instances, helping with network monitoring, forensics, and security.

Dedicated Project: A Google Cloud organizational structure that involves separating resources and services into different projects for security, billing, or administrative purposes.
32.Cloud Identity-Aware Proxy (Cloud IAP): A service that allows you to control access to your web applications and GCP services by verifying a user's identity and determining if that user should be allowed to access the resource.

HTTP Request Headers: Pieces of information about the browser, the requested page, and the server that are passed along with an HTTP request in the form of key-value pairs.

Identity Headers: Special headers used by identity providers and services like Cloud IAP to pass on the identity information of the user making a request to an application or resource.
33.Private Google Access: A feature that allows VM instances on a subnet to reach Google services without a public IP address. It leverages internal routing within GCP to access GCP services.
34.ENVELOPE ENCRYPTION: A security mechanism where a data encryption key (DEK) is used to encrypt data and a separate key encryption key (KEK) is used to encrypt the DEK, enhancing the overall security of sensitive data.

DEK: Data Encryption Key, a symmetric key used for encrypting and decrypting data, designed to be frequently rotated or changed for enhanced security.

KEK: Key Encryption Key, an asymmetric or symmetric key used to encrypt and protect DEKs. It is generally stored and managed in a secure service like a key management system.

CLOUD KMS: A cloud-based key management service that allows you to manage, create, and rotate cryptographic keys for your Cloud resources.
35.Cloud Identity-Aware Proxy: A Google Cloud service for controlling access to applications running on Google Cloud, allowing the enforcement of access policies and the use of multi-factor authentication without a VPN.
36.Firewall Insights: Firewall Insights is part of Network Intelligence Center and provides visibility and recommendations for firewall rule analysis, highlighting unused or redundant rules.

Redundant Rules: Redundant rules in a firewall context refer to rules that are either identical or encompassed by broader rules, possibly leading to inefficiencies.

Shadowed Rules: Shadowed rules are firewall rules that will never match traffic because another rule with a higher priority effectively 'shadows' them.
37.Workload Identity Federation: An authentication method that allows applications running outside Google Cloud to assume an IAM Role without using service account keys, facilitating more secure and maintainable cross-environment access.

Attribute Mapping: The process of associating claims from the external identity provider with IAM roles. It uses constant or expression attributes to ensure consistent access management.

Identity Pools: A federation mechanism that provides a way to create a pool of external identities and associate them with IAM permissions without creating individual IAM users within Google Cloud.
38.Monitoring Sinks: A feature within Google Cloud Monitoring that allows users to create sinks that specify how certain logs are exported to other destinations, such as Cloud Pub/Sub, BigQuery, or Cloud Storage.

Cloud Pub/Sub: A scalable, durable event ingestion and delivery system that serves as a foundation for building event-based systems and streaming analytics pipelines.

Dataflow: A fully managed, serverless, and work-load optimized data processing service used for stream and batch data computations. It's typically used to ingratiate and analyze data streams in real-time.

SNMP: Simple Network Management Protocol is a protocol for network management, designed to manage nodes such as servers, workstations, routers, switches on an IP network.
39.KeyRing: A logical grouping of cryptographic keys in Google Cloud KMS that allows for simplified key management. IAM permissions can be set at the KeyRing level to affect all contained keys.

IAM Permissions: Identity and Access Management permissions determine what actions a user, group, or service account can perform on Google Cloud resources. It is central to controlling access to KMS keys.
40.Service Account Key: An authentication credential used to access Google Cloud services programmatically. It's associated with a service account and used in scenarios where code needs to authenticate and authorize itself.

Access Tokens: These are generated by Google's OAuth 2.0 servers and used in authentication processes to permit applications to act on behalf of a user or service account for a limited time.

Key Invalidation: This involves disabling or revoking the credentials tied to a service account to prevent any further use, which ensures that no new access tokens can be acquired using the compromised key.
41.Data Lifecycle Management: Policies that automate the transition of data to less expensive storage classes or the deletion of data that is no longer required.

Object Lifecycle Policies: Specific rules to manage the storage costs by automatically transitioning objects to different storage classes or expiring them after a certain period.

Nearline/Coldline Storage Classes: Google Cloud Storage options for less frequently accessed data, providing a lower-cost alternative for long-term storage, with retrieval costs incurred on access.
42.Customer-Managed Encryption Key (CMEK): CMEK allows users to create, control, and use their encryption keys to protect data at rest in Google Cloud services, offering heightened security for sensitive information.
43.Service Account: A Google Cloud entity used for server-to-server interactions, providing a level of abstraction away from individual user accounts, offering a secure model for authentication and authorization.

Domain-wide Delegation: An advanced feature that allows a service account to act on behalf of users in a Google Workspace domain without requiring their individual credentials, commonly used for applications that access user data.

Service Account User Role: A role that allows service accounts to run operations as themselves or to impersonate other service accounts within the same project, providing the ability to delegate responsibilities.

Impersonation: The process by which a service account assumes the identity of another account (usually a user) for accessing resources, allowing for actions to be performed as if the service account is the other account.

44.VPC Service Controls: Enhances security for sensitive data in GCP services by creating a security perimeter that controls communication between services and prevents data exfiltration.

Security Perimeter: A feature of VPC Service Controls to define a boundary around resources of GCP services, where data is protected within this boundary.

Domain Restricted Sharing: An Organization Policy that restricts resource sharing within a certain domain, preventing data from being shared with entities outside the specified domain.

Uniform Bucket-level Access: A feature that enforces consistent Access Control Lists (ACLs) across all objects in a Cloud Storage bucket, simplifying permission management.

Private Google Access: Allows VM instances that do not have external IP addresses to reach Google services, such as BigQuery, without using public IPs, solely over Google's private network.

VPC Network Peering: A networking feature in Google Cloud that allows different VPC networks to connect with each other, sharing routes without using external IPs and maintaining network isolation.
45.VPC Network: A VPC network is a virtual version of the traditional physical networks that exist within and interconnect Google Cloud's resources, providing isolation and logical partitioning of resources.

Network Interfaces: Network interfaces allow a network device to interact with a VPC network. In Google Cloud, VM instances can have multiple network interfaces, connecting to different VPC networks.

Intrusion Prevention System (IPS): An IPS is a network security/threat prevention technology that examines network traffic flows to detect and prevent vulnerability exploits.

Network Traffic Inspection: This process involves analyzing the communication between different services and entities within a network to detect malicious activity or performance issues.
46.VPC Service Controls: Advanced security feature that allows users to define a security perimeter around Google Cloud resources to mitigate data exfiltration risks. It restricts the resources' accessibility to other Google Cloud services and external networks.

Security Perimeter: A virtual boundary within VPC Service Controls that encompasses Google Cloud resources and controls the flow of data to and from the resources contained in the perimeter.
47.Secret Manager: A secure and convenient storage system for API tokens, passwords, certificates, and other sensitive data. It allows for centralized and programmatic management of secrets.

Identity and Access Management (IAM): Google Cloud's suite for managing access control by defining who (identity) has what access (role) to which resource.

Customer-Managed Encryption Keys (CMEK): A feature that enables users to create, use, and manage their encryption keys, providing control over data encryption in Google Cloud.

Token Rotation: A security procedure where an API token is replaced with a new token at regular intervals to reduce the risk of token compromise and misuse.
48.Cloud Identity Directory Sync: A tool that synchronizes user accounts from an existing identity provider to Google Cloud Identity, enabling centralized lifecycle management of user identities and access.

Lifecycle Management: The process of managing the entire lifecycle of user identities, including creation, maintenance, and deactivation, often integrated with an identity management system.

Identity Management System: A framework for business processes that facilitates the management of electronic identities. It provides a way to authenticate and authorize users across IT systems.

49. Confidential VM instances: Confidential VMs are a type of Google Cloud computational resource that provides memory encryption in-use. This ensures data is encrypted and protected even during processing, safeguarding sensitive information against unauthorized access.

Organization Policy: Organization policies in Google Cloud provide centralized governance, allowing administrators to set constraints across the entire resource hierarchy. This enforces compliance and manages security configurations for the entire organization.

50. Workload Identity Federation: A feature allowing applications to authenticate with Google Cloud services using their native credentials, relying on an external identity provider rather than using service account keys.

External Identity Provider: A third-party service that offers user authentication. Workload Identity Federation uses these providers, such as GitLab, to authenticate users or services before granting access to Google Cloud resources.

Service Account Key: A cryptographic key provided by Google Cloud for a service account that can be used to authenticate applications and services when accessing Google Cloud resources.

Environment Variables: A dynamic-named value that can affect the way running processes will behave on a computer. For CI/CD, they are used to store configuration settings and credentials.

GitLab CI/CD: A tool built into GitLab for software development through the continuous methodologies: Continuous Integration (CI), Continuous Deployment, and Continuous Delivery (CD).


Set 3
1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
13.
14.
15.
16.
17.
18.
19.
20.
21.
22.
23.
24.
25.
26.
27.
28.
29.
30.
31.
32.
33.
34.
35.
36.
37.
38.
39.
40.
41.
42.
43
44.
45.
46.
47.
48.
49.
50.

Set 4
1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
13.
14.
15.
16.
17.
18.
19.
20.
21.
22.
23.
24.
25.
26.
27.
28.
29.
30.
31.
32.
33.
34.
35.
36.
37.
38.
39.
40.
41.
42.
43
44.
45.
46.
47.
48.
49.
50.


Set 5
1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
13.
14.
15.
16.
17.
18.
19.
20.
21.
22.
23.
24.
25.

Template
1.
2.
3.
4.
5.
6.
7.
8.
9.
10.
11.
12.
13.
14.
15.
16.
17.
18.
19.
20.
21.
22.
23.
24.
25.
26.
27.
28.
29.
30.
31.
32.
33.
34.
35.
36.
37.
38.
39.
40.
41.
42.
43
44.
45.
46.
47.
48.
49.
50.












































































