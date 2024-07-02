Module 0 Introduction

  Professional Cloud security engineer
    - enables organizations to design and implement secure workloads and infrastructure on Google Cloud
    - Through an understanding of security best practices and industry security requirements, this individual:
      - designs
      - develops
      - manages a secure solution by leveraging Google Cloud security technologies. 

    - Proficient:
      - IAM
      - defining org structure and policies
      - Using Google Cloud technologies to provide data protection
      - configuring network security defenses
      - monitoring environments for threat detection
      - incident response
      - security policy as code
      - the secure software development lifecycle
      - enforcing regulatory controls. 

  Cymbal bank
    - a fictional company that is digitally transforming and in the process of designing and developing a secure Google Cloud system

    Needs:
      - determine how to set up and secure operations within a hybrid cloud environment. 
      - working with cloud architects and network engineers to design Cymbal Bank’s cloud environment
      - using recommended security practices that are in compliance with industry regulations
      - configuring Identity and Access Management (IAM) and helping define Cymbal Bank’s organizational structure and policies
      - ensure that Cymbal Bank makes use of Google Cloud technologies for 
        - data protection, 
        - network security and defenses
        - logging
        - managing incident responses

  Cert Benefits
    - gain industry recognition
    - validate your technical expertise
    - take your career to the next level

  
  Professional Cert
    Business
      - design
      - plan
      - ensure feasibility
      - optimize

    technical
      - build
      - deploy
      - manage
    Customer implementation

  Exam guide
    - diagnostic questions for each section
    - 5 total sections
    - each section has several objectives
    - resources available at section objective level


  Tips for Multiple Choice questions
    - read question stem carefully
    - try to anticipate the correct answer
    - more than one answer may be possible
    - take questions at face value
    - pay attention to qualifiers and key words
      - usually
      - available
      - never
      - none
      - the best

Module 1 Configuring Access
  - securing the cloud environment and the data stored therein

  Secure identity and access foundation
    - config cloud identity
      - config to multi factor authentication
    - manage service accounts
    - manage authentication
    - manage/implement authorization controls
    - define resource hierarchy

  Sync Cymbal Bank's identities to Google Cloud
    Cymbal
      - Microsoft Active Directory or LDAP
      - users and groups in your existing directory service

      
      ->GCDS (CRON scheduled one-way sync)

    Users and groups in your Cloud Identity domain

  Configuring Cymbal Bank's single sign-on to Google Cloud
    SAML2 single sign-on configuration
      - federate using SAML2 for Single sign-on(SSO)
      - Active Directory
        - is the Identity provider(IdP) and Google Cloud is the service provider(SP)

  Service accounts provide service access to Google Cloud
    - used as  service ID for workloads running in or outside Google Cloud
      - given access to resources like user and group identities
      - authenticate with private keys
      - leverage google key mngmt for most secure usage

  Organization hierarchy helps organize access control and policy for resources
    - Folders provide for flexible hierarchy of Projects
      - organization policy and access control can be bound at any level and flow downwards

  Organization policy helps restrict to authorized usage
    - organization policies composed of a set of organizational policy constraints can be bound at multiple levels of hierarchy
      - large number of optional constraint types across various Google cloud services
      - policies may be configured for inheritance down hierarchy or not
      - with inheritance, ancestor policy constraints can be overridden or merged

  Bind roles to identities to provide access to resources
    - roles are collections of permissions which align with the required access for an abstract job function
      - facilitate least privilege access control and separation of duties
      - can be bound at org, folder, project or resource level and flow downwards

  IAM conditions to control the where, when, how of access to resources
    - IAM conditions can be added to role bindings to control from where, when, and how the access can be used
      - allows for even better least privilege access control      

  Diagnostic questions
    - undestand this section of the Exam
    - idenitify which areas you should focus on the study plan

    1. Cymbal Bank has acquired a non-banking financial company (NBFC). This NBFC uses Active Directory as their central directory on an on-premises Windows Server. You have been tasked with migrating all the NBFC users and employee information to Cloud Identity. What should you do?
      a. Run Microsoft System Center Configuration Manager (SCCM) on a Compute Engine instance. Leave the channel unencrypted because you are in a secure Google Cloud environment. Deploy Google Cloud Directory Sync on the Compute Engine instance. Connect to the on-premises Windows Server environment from the instance, and migrate users to Cloud Identity. 
      b. Run Configuration Manager on a Compute Engine instance. Copy the resulting configuration file from this machine onto a new Compute Engine instance to keep the production environment separate from the staging environment. Leave the channel unencrypted because you are in a secure Google Cloud environment. Deploy Google Cloud Directory Sync on this new instance. Connect to the on-premises Windows Server environment from the new instance, and migrate users to Cloud Identity.
      c. Use Cloud VPN to connect the on-premises network to your Google Cloud environment. Select an on-premises domain-joined Windows Server. On the domain-joined Windows Server, run Configuration Manager and Google Cloud Directory Sync. Use Cloud VPN’s encrypted channel to transfer users from the on-premises Active Directory to Cloud Identity.
      d. Select an on-premises domain-joined Windows Server. Run Configuration Manager on the domain-joined Windows Server, and copy the resulting configuration file to a Compute Engine instance. Run Google Cloud Directory Sync on the Compute Engine instance over the internet, and use Cloud VPN to sync users from the on-premises Active Directory to Cloud Identity.
      Ans. C
        - If you are in an on-premises environment, you can access Active Directory using LDAP. Google Cloud Directory Sync to Cloud Identity communication will be over an HTTPs channel using Cloud VPN. 

    2. Cymbal Bank has certain default permissions and access for their analyst, finance, and teller teams. These teams are organized into groups that have a set of role-based IAM permissions assigned to them. After a recent acquisition of a small bank, you find that the small bank directly assigns permissions to their employees in IAM. You have been tasked with applying Cymbal Bank’s organizational structure to the small bank. Employees will need access to Google Cloud services. What should you do?
      a. Leave all user permissions as-is in the small bank’s IAM. Use the Directory API in the Google Workspace Admin SDK to create Google Groups. Use a Python script to allocate users to the Google Groups. 
      b. Reset all user permissions in the small bank’s IAM. Use Cloud Identity to create dynamic groups for each of the bank’s teams. Use the dynamic groups’ metadata field for team type to allocate users to their appropriate group with a Python script. 
      c. Reset all user permissions in the small bank’s IAM. Use Cloud Identity to create the required Google Groups. Upgrade the Google Groups to Security Groups. Use a Python script to allocate users to the groups. 
      d. Reset all user permissions in the small bank’s IAM. Use the Directory API in the Google Workspace Admin SDK to create Google Groups. Use a Python script to allocate users to the groups. 
      Ans. B 
        - Use Dynamic Groups to create groups based on Identity attributes, such as department, and place the users in a flat hierarchy. 
        - Dynamic group metadata helps build the structure to identify the users.  

      D(wrong)
        - Using Google Groups from the Workspace Admin SDK Directory APIs allows 
          - access to Google Drive and Docs, but not to Google Cloud resources.


    3. Cymbal Bank leverages Google Cloud storage services, an on-premises Apache Spark Cluster, and a web application hosted on a third-party cloud. The Spark cluster and web application require limited access to Cloud Storage buckets and a Cloud SQL instance for only a few hours per day. You have been tasked with sharing credentials while minimizing the risk that the credentials will be compromised. What should you do?
      a. Create a service account with appropriate permissions. Authenticate the Spark Cluster and the web application as direct requests and share the service account key.
      b. Create a service account with appropriate permissions. Have the Spark Cluster and the web application authenticate as delegated requests, and share the short-lived service account credential as a JWT. 
      c. Create a service account with appropriate permissions. Authenticate the Spark Cluster and the web application as a delegated request, and share the service account key. 
      d. Create a service account with appropriate permissions. Have the Spark Cluster and the web application authenticate as a direct request, and share the short-lived service account credentials as XML tokens.
      Ans. B
        - Delegated requests allow a service account to authenticate into a chain of services
        - Using short-lived service account credentials provides limited access to trusted services.

    4. Cymbal Bank recently discovered service account key misuse in one of the teams during a security audit. As a precaution, going forward you do not want any team in your organization to generate new external service account keys. You also want to restrict every new service account’s usage to its associated Project. What should you do?
      a. Navigate to Organizational policies in the Google Cloud Console. Select your organization. Select iam.disableServiceAccountKeyCreation. Customize the applied to property, and set Enforcement to ‘On’. Click Save. Repeat the process for iam.disableCrossProjectServiceAccountUsage.
      b. Run the gcloud resource-manager org-policies enable-enforce command with the constraints iam.disableServiceAccountKeyCreation, and iam.disableCrossProjectServiceAccountUsage and the Project IDs you want the constraints to apply to.
      c. Navigate to Organizational policies in the Google Cloud Console. Select your organization. Select iam.disableServiceAccountKeyCreation. Under Policy Enforcement, select Merge with parent. Click Save. Repeat the process for iam.disableCrossProjectServiceAccountLienRemoval.
      d. Run the gcloud resource-manager org-policies allow command with the boolean constraints iam.disableServiceAccountKeyCreation and iam.disableCrossProjectServiceAccountUsage with Organization ID.
      Ans. A
        - Boolean constraints help you limit service account usage. Iam. disableServiceAccountKeyCreation will restrict the creation of new external service account keys. 
        - Iam.disableCrossProjectServiceAccountUsage will prevent service accounts from being attached to resources in other projects.
      

    5. Cymbal Bank publishes its APIs through Apigee. Cymbal Bank has recently acquired ABC Corp, which uses a third-party identity provider. You have been tasked with connecting ABC Corp’s identity provider to Apigee for single sign-on (SSO). You need to set up SSO so that Google is the service provider. You also want to monitor and log high-risk activities. Which two choices would you select to enable SSO?
      a. Use openssl to generate public and private keys. Store the public key in an X.509 certificate, and encrypt using RSA or DSA for SAML. Sign in to the Google Admin console, and under Security, upload the certificate.
      b. Use openssl to generate a private key. Store the private key in an X.509 certificate, and encrypt using AES or DES for SAML. Sign in to the Google Workspace Admin Console and upload the certificate.
      c. Use openssl to generate public and private keys. Store the private key in an X.509 certificate, and encrypt using AES or DES for SAML. Sign in to the Google Admin console, and under Security, upload the certificate.
      d. Review Network mapping results, and assign SSO profiles to required users.
      e. Review Network mapping results, and assign SAML profiles to required users.
      Ans. B and E
        - AES and DES are symmetric encryptions and generate only private keys.
        - You need an asymmetric encryption to generate two keys: public and private
        - To upload the certificate, you need to use the Google Admin console, not the Google Workspace Admin Console. 

        - . An SSO profile must be assigned to the selected users.
        - . SAML profiles are assertions and policies to enable SSO profiles. 

    6. You are an administrator for Cymbal Bank’s Mobile Development Team. You want to control how long different users can access the Google Cloud console, the Cloud SDK, and any applications that require user authorization for Google Cloud scopes without having to reauthenticate. More specifically, you want users with elevated privileges (project owners and billing administrators) to reauthenticate more frequently than regular users at the organization level. What should you do?
      a. Open all Google Cloud projects that belong to Cymbal Bank’s Mobile Development team. Find each project’s Google Cloud session control setting, and configure a reauthentication policy that requires reauthentication. Choose the reauthentication frequency from the drop-down list.
      b. In the Admin console, select Google Cloud session control and set a reauthentication policy that requires reauthentication. Choose the reauthentication frequency from the drop-down list.
      c. Create a custom role for project owners and billing administrators at the organization level in the Google Cloud console. Add the reauthenticationRequired permission to this role. Assign this role to each project owner and billing administrator.
      d. Create a custom role for project owners and billing administrators at the organization level in the Google Cloud console. Add the reauthenticationRequired permission to this role. Create a Google Group that contains all billing administrators and project owners. Apply the custom role to the group.
      Ans. d(wrong)
        - While applying roles to Google Groups is a best practice, the reauthenticationRequired permission does not exist. Your set reauthentication policies are configured in the Admin console. 

      B
        - Session control settings are configured in the Admin console. These settings will be set at the organization level and will include all project owners and billing administrators in the organization. 

    7. Cymbal Bank’s organizational hierarchy divides the Organization into departments. The Engineering Department has a ‘product team’ folder. This folder contains folders for each of the bank’s products. Each product folder contains one Google Cloud Project, but more may be added. Each project contains an App Engine deployment. 
    Cymbal Bank has hired a new technical product manager and a new web developer. The technical product manager must be able to interact with and manage all services in projects that roll up to the Engineering Department folder. The web developer needs read-only access to App Engine configurations and settings for a specific product. How should you provision the new employees’ roles into your hierarchy following principles of least privilege?
      A.Assign the Project Editor role in each individual project to the technical product manager. Assign the Project Editor role in each individual project to the web developer.
      B.Assign the Project Owner role in each individual project to the technical product manager. Assign the App Engine Deployer role in each individual project to the web developer.
      C.Assign the Project Editor role at the Engineering Department folder level to the technical product manager. Assign the App Engine Deployer role at the specific product’s folder level to the web developer.
      D.Assign the Project Editor role at the Engineering Department folder level to the technical product manager. Create a Custom Role in the product folder that the web developer needs access to. Add the appengine.versions.create and appengine.versions.delete permissions to that role, and assign it to the web developer.
      Ans. d(wrong)
      - Although the correct permissions are assigned to the technical product manager, the web developer is provided permissions that are overly permissive. Custom roles are also not required because the App Engine Deployer role gives the web developer all the required permissions. 

      C
        -  Because the technical product manager must be able to work with services across all projects, you should provide permissions at the Department folder level. The web developer should only be able to administer App Engine deployments in their product folder.

    8. Cymbal Bank’s organizational hierarchy divides the Organization into departments. The Engineering Department has a ‘product team’ folder. This folder contains folders for each of the bank’s products. One folder titled “analytics” contains a Google Cloud Project that contains an App Engine deployment and a Cloud SQL instance. 
    A team needs specific access to this project. The team lead needs full administrative access to App Engine and Cloud SQL. A developer must be able to configure and manage all aspects of App Engine deployments. There is also a code reviewer who may periodically review the deployed App Engine source code without making any changes. What types of permissions would you provide to each of these users?
      a.Create custom roles for all three user types at the “analytics” folder level. For the team lead, provide all appengine.* and cloudsql.* permissions. For the developer, provide appengine.applications.* and appengine.instances.* permissions. For the code reviewer, provide the appengine.instances.* permissions.
      b.Assign the basic ‘App Engine Admin’ and ‘Cloud SQL Admin” roles to the team lead. Assign the ‘App Engine Admin’ role to the developer. Assign the ‘App Engine Code Viewer’ role to the code reviewer. Assign all these permissions at the analytics project level. 
      c.Create custom roles for all three user types at the project level. For the team lead, provide all appengine.* and cloudsql.* permissions. For the developer, provide appengine.applications.* and appengine.instances.* permissions. For the code reviewer, provide the appengine.instances.* permissions. 
      d.Assign the basic ‘Editor’ role to the team lead. Create a custom role for the developer. Provide all appengine.* permissions to the developer. Provide the predefined ‘App Engine Code Viewer’ role to the code reviewer. Assign all these permissions at the “analytics” folder level.
      Ans. B 
        - Assign the basic ‘App Engine Admin’ and ‘Cloud SQL Admin” roles to the team lead. Assign the ‘App Engine Admin’ role to the developer. Assign the ‘App Engine Code Viewer’ role to the code reviewer. Assign all these permissions at the analytics project level. 

      d(wrong)
      - The basic ‘Editor’ role is too coarse-grained for the team lead. The Developer needs the predefined role of ‘App Engine Admin’. You can assign the ‘App Engine Code Viewer’ for the code reviewer; a custom role is not required. Permissions also need to be set at the project, not folder, level.

      

    9. Cymbal Bank is divided into separate departments. Each department is divided into teams. Each team works on a distinct product that requires Google Cloud resources for development. How would you design a Google Cloud organization hierarchy to best match Cymbal Bank’s organization structure and needs?
      a.Create an Organization node. Under the Organization node, create Department folders. Under each Department, create Product folders. Under each Product, create Teams folders. In the Teams folder, add Projects. 
      b.Create an Organization node. Under the Organization node, create Department folders. Under each Department, create Product folders. Add Projects to the Product folders. 
      c.Create an Organization node. Under the Organization node, create Department folders. Under each Department, create Teams folders. Add Projects to the Teams folders. 
      d.Create an Organization node. Under the Organization node, create Department folders. Under each Department, create a Teams folder. Under each Team, create Product folders. Add Projects to the Product folders. 
      Ans. D
        - epartments have teams, which work on products. This hierarchy best fits Cymbal Bank’s organization structure.
      
      B(wrong)
        - This hierarchy is missing the Teams layer.

    10. Cymbal Bank has a team of developers and administrators working on different sets of Google Cloud resources. The Bank’s administrators should be able to access the serial ports on Compute Engine Instances and create service accounts. Developers should only be able to access serial ports. How would you design the organization hierarchy to provide the required access?
      a.Deny Serial Port Access and Service Account Creation at the Organization level. Create an ‘admin’ folder and set enforced: false for constraints/compute.disableSerialPortAccess. Create a new ‘dev’ folder inside the ‘admin’ folder, and set enforced: false for constraints/iam.disableServiceAccountCreation. Give developers access to the ‘dev’ folder, and administrators access to the ‘admin’ folder.
      b.Deny Serial Port Access and Service Account Creation at the organization level. Create a ‘dev’ folder and set enforced: false for constraints/compute.disableSerialPortAccess. Create a new ‘admin’ folder inside the ‘dev’ folder, and set enforced: false for constraints/iam.disableServiceAccountCreation. Give developers access to the ‘dev’ folder, and administrators access to the ‘admin’ folder.
      c.Deny Serial Port Access and Service Account Creation at the organization level. Create a ‘dev’ folder and set enforced: true for constraints/compute.disableSerialPortAccess and enforced: true for constraints/iam.disableServiceAccountCreation. Create a new ‘admin’ folder inside the ‘dev’ folder, and set enforced: false for constraints/iam.disableServiceAccountCreation. Give developers access to the ‘dev’ folder, and administrators access to the ‘admin’ folder.
      d.Allow Serial Port Access and Service Account Creation at the organization level. Create a ‘dev’ folder and set enforced: true for constraints/iam.disableServiceAccountCreation. Create another ‘admin’ folder that inherits from the parent inside the organization node. Give developers access to the ‘dev’ folder, and administrators access to the ‘admin’ folder.
      Ans. B
        - These organizational constraints will prevent all users from accessing serial ports on Compute Engine instances and creating service accounts.
        - You can override these constraints in a new folder by setting the common constraint for serial port access.
        - Creating another folder inside a parent folder will allow you to inherit the constraint and will allow you to add additional constraints to create a service account
        - Accountdmins and developers are added appropriately.
      
      D(wrong)
        - Allowing Serial Port Access and Service Account Creation at the organization level defeats the problem statement, which specifies that only the bank’s Administrators should be able to access the serial ports on Compute Engine Instances and create service accounts. You should ‘DENY’ the permissions at the organization level and enable them at the folder or Project level.

    First take
      4/10

    Planning Cymbal Bank's cloud identity and access management
    Role
      - secure the cloud env and tje 

    Knowledge Check
    Practice quiz
    1. Which tool will Cymbal Bank use to synchronize their identities from their on-premise identity management system to Google Cloud?
      - Google Cloud Directory Sync
        - synchronize identities from their on-premises Active Directory system to Google Cloud.

      
      - Cloud Identity
        - is Google’s identity management system and can’t be used to synchronize external identities to Google Cloud, although it can receive imported identities.
    
    2. Which feature of Google Cloud will Cymbal Bank use to control the source locations and times that authorized identities will be able to access resources?
      - IAM Conditions
        - let Cymbal Bank control when or from where authorized identities can access resources.

      - IAM Roles 
        - are necessary to authorize identities to access resources, but can’t be used alone to control when or from where the authorized identities can access the resources.

      - Service Accounts 
        - are service identities in Google Cloud, and can’t be used to control when or from where authorized identities can access resources.

      - Identity-aware Proxy
        -  is a service that can be used to provide authentication and authorization for access to resources.

  Module 1 Configuring Access to read
	4/10

	Question 2 asked you to create dynamic groups in Cloud Identity

	1.1 Managing Cloud Identity

	Considerations include: 
		● Configuring Google Cloud Directory Sync and third-party connectors 
		● Managing a super administrator account 
		● Automating the user lifecycle management process 
		● Administering user accounts and groups programmatically 
		● Configuring Workforce Identity Federation

	
	To read:
		● https://support.google.com/a/answer/10286834
		● https://cloud.google.com/identity/docs/how-to/create-dynamic-groups
		● https://support.google.com/a/answer/10427204


	Summary:
		Cloud Identity 
			- supports creating groups 
			- and then placing users inside those groups.
		
		Groups 
			- help with 
				- managing permissions
				- access controls,
				- organizational policies.
		
		In Dynamic Groups, 
			- users are automatically managed and 
			- added based on 
				- Identity attributes, such as department.

	Additional:	
		● https://cloud.google.com/architecture/identity/federating-gcp-with-active-direct
		ory-synchronizing-user-accounts
		● https://support.google.com/a/answer/6126578?hl=en#:~:text=Configuration%20Manager%20is%20a%20step,test%2C%20and%20run%20a%20synchronization
		● https://support.google.com/a/answer/10286834
		● https://cloud.google.com/identity/docs/how-to/create-dynamic-groups
		● https://support.google.com/a/answer/10427204
	
	Question 6 tested your knowledge of the steps to create custom IAM roles.

	1.3 Managing authentication
	
	Considerations include: 
		● Creating a password and session management policy for user accounts 
		● Setting up Security Assertion Markup Language (SAML) and OAuth 
		● Configuring and enforcing two-step verification

	To read:
		● https://support.google.com/a/answer/9368756?hl=en

	Summary:
		As an administrator, you can control how long different users can access the Google
		Cloud console and Cloud SDK without having to reauthenticate. For example, you
		might want users with elevated privileges, like project owners, billing administrators,
		or others with administrator roles, to reauthenticate more frequently than regular
		users. If you set a session length, they’re prompted to sign in again to start a new 
		session.
		
		The session length setting applies to:
			● The Google Cloud console
			● The gcloud command-line tool (Cloud SDK)
			● Any applications (including third-party applications, or your own applications)
			that require user authorization for Google Cloud scopes. To review the apps
			requiring Google Cloud scopes in the Apps access control UI, see Control
			which third-party & internal apps access Google Workspace data.

	Additional:	
		● https://cloud.google.com/apigee/docs/api-platform/system-administration samloverview
		● https://support.google.com/a/answer/60224
		● https://support.google.com/a/answer/10723804
		● https://support.google.com/a/answer/6369487
		● https://cloud.google.com/iam/docs/creating-custom-roles
		● https://cloud.google.com/iam/docs/understanding-custom-roles
		● https://cloud.google.com/iam/docs/understanding-roles#billing-roles

	1.4 Managing and implementing authorization controls 

	Considerations include: 
		● Managing privileged roles and separation of duties with Identity and Access Management (IAM) roles and permissions 
		● Managing IAM and access control list (ACL) permissions 
		● Granting permissions to different types of identities, including using IAM conditions and IAM deny policies 
		● Designing identity roles at the organization, folder, project, and resource level ● Configuring Access Context Manager 
		● Applying Policy Intelligence for better permission management 
		● Managing permissions through groups

	Question 7 tested your understanding of using roles at different levels of an organizational hierarchy. 

	To read:		
		● https://cloud.google.com/resource-manager/docs/access-control-proj
		● https://cloud.google.com/resource-manager/docs/access-control-org
		● https://cloud.google.com/resource-manager/docs/access-control-folders
	
	Question 8 asked you to select basic, predefined, or custom IAM roles for a specific scenario.

	Where to look:
		● https://cloud.google.com/iam/docs/understanding-roles
		● https://cloud.google.com/iam/docs/understanding-roles#app-engine-roles


	Summary:
		IAM roles are of 3 types: basic, predefined, and custom. Basic roles of ‘Owner,’
		‘Editor,’ and ‘Viewer’ provide a large set of broad permissions that existed before IAM.
		Most often, basic roles are not recommended because of the large number of
		permissions they contain. Predefined roles limit the permissions and access that a
		role has and are defined separately for each Google Cloud resource. Create custom
		roles when the predefined roles provide more permission than required.


	Additional:
		● https://cloud.google.com/resource-manager/docs/access-control-proj
		● https://cloud.google.com/resource-manager/docs/access-control-org
		● https://cloud.google.com/resource-manager/docs/access-control-folders
		● https://cloud.google.com/iam/docs/understanding-roles
		● https://cloud.google.com/iam/docs/understanding-roles#app-engine-roles


	1.5 Defining resource hierarchy
	
	Considerations include: 
		● Creating and managing organizations at scale 
		● Managing organization policies for organization folders, projects, and resources 
		● Using resource hierarchy for access control and permissions inheritance


	Question 9 asked you to create a resource hierarchy that aligns with a given organizational structure and access control requirements. Question 10 tested your knowledge of designing a hierarchy and policies to control access to Google Cloud resources.

	Where to look:
		https://cloud.google.com/resource-manager/docs/organization-policy/understanding-hierarchy

	Summary:
		Organization hierarchy helps build an inheritance of policies and permissions.
		Although Projects can be placed directly in an Organization, creating layers of folders
		in between helps with managing different permissions for different access. You can
		also use folders to derive an inheritance of policies and permissions.

	Question 10 tested your knowledge of designing a hierarchy and policies to control access to Google Cloud resources.

	Where to look:
		● https://cloud.google.com/resource-manager/docs/creating-managing-organization
		● https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organiz
		ations

	Summary:
		Organization hierarchies allow you to place lists and boolean constraints. These
		constraints can be inherited into folders and subsequently into sub-folders and
		Projects.

	Additional:	
		● https://cloud.google.com/resource-manager/docs/organization-policy/understanding-hierarchy
		● https://cloud.google.com/resource-manager/docs/creating-managing-organization
		● https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations

Module 2 Securing Communications and Establishing Boundary Protection
  Securing Cymbal Bank's Network resources
    - design network security
    - configure network segmentation
    - establish private connectivity

    To dos:
      - Provide Layer 3 + Layer 4 DDoS defense
        - HTTPS load balancer for layer 3 adn 4 protection
      - Provide Layer 7 DDoS defense
        - Cloud armor 
      - Protect against SQL injection attacks
        - Cloud armor 
      - Protect against XSS injection attacks
        - Cloud armor 
      - Configure rules for filtering traffic
        - Cloud armor 
      - Ensure traffic arriving from public internet goes through:
        - HTTPS LB
        - Cloud armor for extra protection
      - Users from public internet connect through 
        - Identity-Aware roxy
          - authentication and authorization
      - Protect public DNS zones through
        - Cloud DNS
          - supports DNSSEC
            - secure DNS resources and prevent attackers from manipulating DNS responses.
          - ensures authenticated DNS responses to DNS requests
          - automatically manages DNSSEC related DNS records
          - integrates w/ DNSSEC at the domain registrar level

      - use firewall rules to only 
        - allow valid and expected traffic betwee workloads
        - and block all other traffic
        - stateful rules 
          - handle requests in either the ingress or egress direction
        - restric traffic to specific source and target SA
        - hierarchical FW rules ensure uniform app of rules across projects

      - Isolate networks to secure workloads
        - cymbal bank will connect privately across projects using shared VPC and VPC peering.

      - Keep traffic private where possible
        - connect privately from on-premises into google cloud to google APIs or the wider internet
        - cloud VPN adn interconnect
        - google private access
        - cloud NAT

  Diagonistic questions 
  Practice Exam
  1. Cymbal Bank has published an API that internal teams will use through the HTTPS load balancer. You need to limit the API usage to 200 calls every hour. Any exceeding usage should inform the users that servers are busy. Which gcloud command would you run to throttle the load balancing for the given specification?
    A. gcloud compute security-policies rules create priority 
      --security-policy sec-policy    
      --src-ip-ranges=source-range    
      --action=rate-based-ban 
      --rate-limit-threshold-count=200 
      --rate-limit-threshold-interval-sec=3600 
      --conform-action=deny 
      --exceed-action=deny-403    
      --enforce-on-key=HTTP-HEADER
    B. gcloud compute security-policies rules create priority 
      --security-policy sec-policy    
      --src-ip-ranges=source-range   
      --action=throttle
      --rate-limit-threshold-count=200 
      --rate-limit-threshold-interval-sec=3600 
      --conform-action=allow    
      --exceed-action=deny-429 
      --enforce-on-key=HTTP-HEADER 
    C. gcloud compute security-policies rules create priority 
      --security-policy sec-policy    
      --src-ip-ranges="<source range>"    \
      --action=rate-based-ban 
      --rate-limit-threshold-count=200 
      --rate-limit-threshold-interval-sec=3600 
      --conform-action=allow 
      --exceed-action=deny-500    
      --enforce-on-key=IP 
    D. gcloud compute security-policies rules create priority 
      --security-policy sec-policy    
      --src-ip-ranges=source-range   
      --action=throttle    
      --rate-limit-threshold-count=200 
      --rate-limit-threshold-interval-sec=60 
      --conform-action=deny 
      --exceed-action=deny-404    
      --enforce-on-key=HTTP-HEADER
    Ans. b
      - 
    
    A(Wrong)
      - Rate-based-ban would be helpful if you wanted to disable the incoming services for a time period. 
      - You need a throttle limit. Error 403 is incorrect; 
      - it indicates invalid authorization, which is not your use case. 
      - Action should be allowed, not denied.


  2.Cymbal Bank is releasing a new loan management application using a Compute Engine managed instance group. External users will connect to the application using a domain name or IP address protected with TLS 1.2. A load balancer already hosts this application and preserves the source IP address. You are tasked with setting up the SSL certificate for this load balancer. What should you do?
    A. Create a Google-managed SSL certificate. Attach a global dynamic external IP address to the internal HTTPS load balancer. Validate that an existing URL map will route the incoming service to your managed instance group backend. Load your certificate and create an HTTPS proxy routing to your URL map. Create a global forwarding rule that routes incoming requests to the proxy.
    B. Create a Google-managed SSL certificate. Attach a global static external IP address to the external HTTPS load balancer. Validate that an existing URL map will route the incoming service to your managed instance group backend. Load your certificate and create an HTTPS proxy routing to your URL map. Create a global forwarding rule that routes incoming requests to the proxy.
    C. Import a self-managed SSL certificate. Attach a global static external IP address to the TCP Proxy load balancer. Validate that an existing URL map will route the incoming service to your managed instance group backend. Load your certificate and create a TCP proxy routing to your URL map. Create a global forwarding rule that routes incoming requests to the proxy.
    D. Import a self-managed SSL certificate. Attach a global static external IP address to the SSL Proxy load balancer. Validate that an existing URL map will route the incoming service to your managed instance group backend. Load your certificate and create an SSL proxy routing to your URL map. Create a global forwarding rule that routes incoming requests to the proxy.
    Ans. B
      - Attaching a global static external IP address will expose your load balancer to internet users. 
      - Creating HTTPS proxy (and global forwarding rules) will help route the request to the existing backend.

  3. Your organization has a website running on Compute Engine. This instance only has a private IP address. You need to provide SSH access to an on-premises developer who will debug the website from the authorized on-premises location only. How do you enable this?
    A. Use Identity-Aware Proxy (IAP). Set up IAP TCP forwarding by creating ingress firewall rules on port 22 for TCP using the gcloud command.
    B. Set up Cloud VPN. Set up an unencrypted tunnel to one of the hosts in the network. Create outbound or egress firewall rules. Use the private IP address to log in using a gcloud ssh command.
    C. Use SOCKS proxy over SSH. Set up an SSH tunnel to one of the hosts in the network. Create the SOCKS proxy on the client side.
    D. Use the default VPC’s firewall. Open port 22 for TCP protocol using the Google Cloud Console.
    Ans. A
      - IAP TCP forwarding establishes an encrypted tunnel that supports both SSH and RDP requests.

  4. You have recently joined Cymbal Bank as a cloud engineer. You created a custom VPC network, selecting to use the automatic subnet creation mode and nothing else. The default network still exists in your project. You create a new Linux VM instance and select the custom VPC as the network interface. You try to SSH into your instance, but you are getting a “connection failed” error. What answer best explains why you cannot SSH into the instance?
    A. You should have used the default network when setting up your instance. While custom networks support instance creation, they should only be used for internal communication.
    B. You should have deleted the default network. When you have multiple VPCs in your project, Compute Engine can’t allow you to connect because overlapping IP ranges prevent the API from establishing a root connection.
    C. You should have used custom subnet creation mode. Since the default VPC still exists, automatic mode created subnets in the same regions, which led to overlapping IP addresses.
    D. You did not set up any firewall rules on your custom VPC network. While the default VPC comes with a predefined firewall rule that allows SSH traffic, these need to be added to any custom VPCs.
    Ans. D
      - You did not create any firewalls to allow SSH traffic. 

  5. Cymbal Bank needs to connect its employee MongoDB database to a new human resources web application on the same network. Both the database and the application are autoscaled with the help of Instance templates. As the Security Administrator and Project Editor, you have been tasked with allowing the application to read port 27017 on the database. What should you do?
    A. Create a user account for the database admin and a service account for the application. Create a firewall rule using:
    gcloud compute firewall-rules create ALLOW_MONGO_DB 
      --network network-name 
      --allow TCP:27017 
      --source-service-accounts web-application-service-account 
      --target-service-accounts database-admin-user-account
    B. Create service accounts for the application and database. Create a firewall rule using:
    gcloud compute firewall-rules create ALLOW_MONGO_DB 
      --network network-name 
      --allow TCP:27017 
      --source-service-accounts web-application-service-account 
      --target-service-accounts database-service-account
    C. Create user accounts for the application and database. Create a firewall rule using:
    gcloud compute firewall-rules create ALLOW_MONGO_DB 
      --network network-name 
      --deny UDP:27017 
      --source-service-accounts web-application-user-account 
      --target-service-accounts database-admin-user-account
    D. Create service accounts for the application and database. Create a firewall rule using:
    gcloud compute firewall-rules create ALLOW_MONGO_DB 
      --network network-name 
      --allow ICMP:27017 
      --source-service-accounts web-application-service-account
      --target-service-accounts database-service-account
    Ans. B
      - Use service accounts to automate the identification, authentication, and authorization process between the n-tier services. 
      - Allow TCP protocol on the port for reading.

  6. Cymbal Bank has designed an application to detect credit card fraud that will analyze sensitive information. The application that’s running on a Compute Engine instance is hosted in a new subnet on an existing VPC. Multiple teams who have access to other VMs in the same VPC must access the VM. You want to configure the access so that unauthorized VMs or users from the internet can’t access the fraud detection VM. What should you do?
    A. Use subnet isolation. Create a service account for the fraud detection engine. Create service accounts for each of the teams’ Compute Engine instances that will access the engine. Add a firewall rule using: 
      gcloud compute firewall-rules create ACCESS_FRAUD_ENGINE 
        --network <network name> 
        --allow TCP:80 
        --source-service-accounts <list of service accounts> 
        --target-service-accounts <fraud detection engine’s service account>
    B. Use target filtering. Create a tag called ‘app’, and assign the tag to both the source and the target. Create a firewall rule to allow all ingress communication on this tag.
    C. Use subnet isolation. Create a service account for the fraud detection VM. Create one service account for all the teams’ Compute Engine instances that will access the fraud detection VM. 
      Create a new firewall rule using:
      gcloud compute firewall-rules create ACCESS_FRAUD_ENGINE 
        --network <network name> 
        --allow TCP:80 
        --source-service-accounts <one service account for all teams>
        --target-service-accounts <fraud detection engine’s service account>
    D. Use target filtering. Create two tags called ‘app’ and ‘data’. Assign the ‘app’ tag to the Compute Engine instance hosting the Fraud Detection App (source), and assign the ‘data’ tag to the other Compute Engine instances (target). Create a firewall rule to allow all ingress communication on this tag.
    Ans. A
      - Using subnet isolation, you have to authorize every request entering your subnet. 
      - The recommended solution is to create a firewall rule that allows only a limited set of service accounts to access the shared target.

  7. The data from Cymbal Bank’s loan applicants resides in a shared VPC. A credit analysis team uses a CRM tool hosted in the App Engine standard environment. You need to provide credit analysts with access to this data. You want the charges to be incurred by the credit analysis team. What should you do?
    A. Add ingress firewall rules to allow NAT and Health Check ranges for App Engine standard environment in the Shared VPC network. Create a server-side connector in the Host Project using the Shared VPC Project ID. Verify that the connector is in a READY state. Create an ingress rule on the Shared VPC network to allow the connector using Network Tags or IP ranges.
    B. Add egress firewall rules to allow SSH and/or RDP ports for the App Engine standard environment in the Shared VPC network. Create a client-side connector in the Service Project using the IP range of the target VPC. Verify that the connector is in a READY state. Create an egress rule on the Shared VPC network to allow the connector using Network Tags or IP ranges.
    C. Add egress firewall rules to allow TCP and UDP ports for the App Engine standard environment in the Shared VPC network. Create either a client-side connector in the Service Project or a server-side connector in the Host Project using the IP Range or Project ID of the target VPC. Verify that the connector is in a READY state. Create an egress rule on the Shared VPC network to allow the connector using Network Tags or IP ranges.
    D. Add ingress firewall rules to allow NAT and Health Check ranges for the App Engine standard environment in the Shared VPC network. Create a client-side connector in the Service Project using the Shared VPC Project ID. Verify that the connector is in a READY state. Create an ingress rule on the Shared VPC network to allow the connector using Network Tags or IP ranges.
    Ans. D
      - App Engine uses a fixed set of NAT and health check IP address ranges that must be permitted into the VPC. 
      - Because the charges must be incurred by the credit analysis team, you need to create the connector on the client side.

  8. Cymbal Bank’s Customer Details API runs on a Compute Engine instance with only an internal IP address. Cymbal Bank’s new branch is co-located outside the Google Cloud points-of-presence (PoPs) and requires a low-latency way for its on-premises apps to consume the API without exposing the requests to the public internet. Which solution would you recommend?
    A. Use Carrier Peering. Use a service provider to access their enterprise grade infrastructure to connect to the Google Cloud environment.
    B. Use Partner Interconnect. Use a service provider to access their enterprise grade infrastructure to connect to the Google Cloud environment.
    C. Use Dedicated Interconnect. Establish direct peering with one of Google’s nearby edge-enabled PoPs.
    D. Use a Content Delivery Network (CDN). Establish direct peering with one of Google’s nearby edge-enabled PoPs.
    Ans. B
      - When you are co-located in one of the Google Cloud PoPs, use Direct Interconnect. 
      - Otherwise, use Partner Interconnect to connect to Google Cloud with a private IP address.

  9. An external audit agency needs to perform a one-time review of Cymbal Bank’s Google Cloud usage. The auditors should be able to access a Default VPC containing BigQuery, Cloud Storage, and Compute Engine instances where all the usage information is stored. You have been tasked with enabling the access from their on-premises environment, which already has a configured VPN. What should you do?
    A. Use a Cloud VPN tunnel. Use your DNS provider to create DNS zones and records for private.googleapis.com. Connect the DNS provider to your on-premises network. Broadcast the request from the on-premises environment. Use a software-defined firewall to manage incoming and outgoing requests. 
    B. Use Dedicated Interconnect. Configure a VLAN in the auditor's on-premises environment. Use Cloud DNS to create DNS zones and records for restricted.googleapis.com and private.googleapis.com. Set up on-premises routing with Cloud Router. Add custom static routes in the VPC to connect individually to BigQuery, Cloud Storage, and Compute Engine instances.
    C. Use Partner Interconnect. Configure an encrypted tunnel in the auditor's on-premises environment. Use Cloud DNS to create DNS zones and A records for private.googleapis.com.
    D. Use a Cloud VPN tunnel. Use Cloud DNS to create DNS zones and records for *.googleapis.com. Set up on-premises routing with Cloud Router. Use Cloud Router custom route advertisements to announce routes for Google Cloud destinations.
    Ans. D
      - Cloud VPN provides a cost-effective and easily set-up environment for on-premises users to access Google Cloud privately. 
      - Using *.googleapis.com enables requests for both private.googleapis.com and restricted.googleapis.com
      - Use Cloud Router to set up and announce Google Cloud routes on-premises.

  10. An ecommerce portal uses Google Kubernetes Engine to deploy its recommendation engine in Docker containers. This cluster instance does not have an external IP address. You need to provide internet access to the pods in the Kubernetes cluster. What configuration would you add?
    A. Cloud NAT gateway, subnet primary IP address range for nodes, and subnet secondary IP address range for pods and services in the cluster 
    B. Nginx load balancer, subnet secondary IP address range for nodes, and subnet secondary IP address range for pods and services in the cluster 
    C. Cloud DNS, subnet primary IP address range for nodes, and subnet secondary IP address range for pods and services in the cluster 
    D. Cloud VPN, subnet secondary IP address range for nodes, and subnet secondary IP address range for pods and services in the cluster 
    ANS. A
      - Cloud NAT gateways help provide internet access (outbound) without requiring a public IP address. 

  Knowledge Check
  Quiz
  1. Which tool will Cymbal Bank use to enforce authentication and authorization for services deployed to Google Cloud?
    - Identity-Aware proxy
      - provides authentication and authorization for services deployed to Google Cloud.

  2. How will Cymbal Bank enable resources with only internal IP addresses to make requests to the Internet?
    - Cloud NAT 
      - is primarily intended for enabling resources with only internal IP addresses to make requests to the Internet.

    - Google private access
      - allows resources with only internal IP addresses to make requests to Google APIs but not to the wider Internet.

Module 3 Ensuring Data Protection

  Knowledge Check
  Quiz
  1. Which tool will Cymbal Bank use to scan for, detect, and optionally transform sensitive data to prevent exposure?
    - Sensitive Data Protection
      - intended for scanning, detecting and optionally transforming sensitive data to prevent exposure.

  2. What feature will allow Cymbal Bank to delete or change the storage class of objects in Cloud Storage buckets?
    - Lifecycle management rules
      - automatically delete or change the storage class of objects based on age or other factors.

Module 4 Managing Operations

Module 5 Supporting ocmpliance Requirements

Module 6 Your NExt steps