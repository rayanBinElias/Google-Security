To read

Module 1 Configuring Access to read
	Score
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
		session

		
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
	Score
		9/10

	 Question 1: securing load balancers and backends using firewall
  2.1 Designing and configuring perimeter security
    Considerations include: 
      ● Configuring network perimeter controls (firewall rules, hierarchical firewall policies, Identity-Aware Proxy (IAP), load    balancers, and Certificate Authority Service) 
      ● Differentiating between private and public IP addressing 
      ● Configuring web application firewall (Google Cloud Armor) 
      ● Deploying Secure Web Proxy ● Configuring Cloud DNS security settings 
      ● Continually monitoring and restricting configured APIs

  Where to look:
    ● https://cloud.google.com/sdk/gcloud/reference/compute/security-policies/rules/update
    ● https://cloud.google.com/sdk/gcloud/reference/compute/security-policies

  Summary:
    Google Cloud Armor provides capabilities to help protect your Google Cloud
    applications against a variety of Layer 3 and Layer 7 attacks. Google Cloud Armor
    security policies filter incoming traffic that is destined to global external HTTP(S) load
    balancers or global external HTTP(S) load balancer (classic)s. Rate-based rules help
    you protect your applications from a large volume of requests that flood your
    instances and block access for legitimate users.

  Additional:
    ● https://cloud.google.com/sdk/gcloud/reference/compute/security-policies/rules/update
    ● https://cloud.google.com/sdk/gcloud/reference/compute/security-policies
    ● https://cloud.google.com/load-balancing/docs/https/ext-https-lb-simple
    ● https://cloud.google.com/load-balancing/docs/ssl-certificates/google-managedcerts#load-balancer
    ● https://cloud.google.com/iap/docs/using-tcp-forwarding#preparing_your_project_for_tcp_forwarding
    ● https://cloud.google.com/solutions/connecting-securely#preventing_vms_from_being_reached_from_the_public_internet


Module 3 Ensuring Data Protection


  