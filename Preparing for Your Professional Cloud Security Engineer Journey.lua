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

Module 2 Securing Communications and Establishing Boundary Protection
  Securing Cymbal Bank's Network resources

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
    B. Create service accounts for the application and database. Create a firewall rule using:
      gcloud compute firewall-rules create ALLOW_MONGO_DB 

        --network network-name 

        --allow TCP:27017 

        --source-service-accounts web-application-service-account 

        --target-service-accounts database-service-account
    C.
    D.
    Ans . 

  2.
    -

  3.
    -

  4.

Module 3 Ensuring Data Protection

Module 4 Managing Operations

Module 5 Supporting ocmpliance Requirements

Module 6 Your NExt steps