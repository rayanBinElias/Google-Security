Professional Cloud Security Engineer exam preparation manual. Exam trends and study methods

Overview
  - 120 minutes
  - 20 questions
    - plenty of time to answer them calmly

Foundation
  - Organizations (Policy constraints) 
  - VPC
  - Cloud Identity
  - Google Cloud Directory Sync (GCDS)
  - Cloud KMS 
  - Cloud DLP

  - encryption
  - network
  - web app security

Shared Responsibility Model Resources to read
  Enterprise foundations blueprint 
    - https://cloud.google.com/architecture/security-foundations

  PCI DSS
    - Google Cloud - How does Google Cloud support my organization's PCI DSS compliance efforts?

  AWS sHared responsibility Model
    - https://aws.amazon.com/jp/compliance/shared-responsibility-model/

Organizational policies
  - Policy inheritance between parent and child resources
    - https://cloud.google.com/resource-manager/docs/organization-policy/understanding-hierarchy

  - How to use the most common policies, as described in the official How-to guides
    Restricting Identities by Domain
      - https://cloud.google.com/resource-manager/docs/organization-policy/restricting-domains
    Restricting use of service accounts
      - https://cloud.google.com/resource-manager/docs/organization-policy/restricting-service-accounts
    Resource Location Restrictions
      - https://cloud.google.com/resource-manager/docs/organization-policy/defining-locations

  Domain Restricted Sharing, when allowing an external domain:
    - you add the external domain to the rule as an exception, 
    - but it is important to understand that you specify it by its Google Workspace/Cloud Identity customer ID (alphanumeric characters) rather than by its domain name.

  service account-related rule:
    - separate rules:
      - the creation of service accounts themselves 
      - rules restricting the creation of service account keys 

Cloud Identity and identity federation
Identity and Access Management (IAM)
VPC
Concepts to keep in mind
point
References
Cloud Interconnect (Cloud VPN) and Private Google Access
encryption
Cloud KMS (Key Management Service)
Envelope Encryption
Default and CMEK encryption
Confidential Computing
Preventing personal information leaks
Cloud DLP
Cloud DLP anonymization feature
DevSecOps (CI/CD)
Other services you should keep in mind
Cloud Armor
Cloud Load Balancing
VPC Service Controls
Security Command Center
Network Intelligence Center
Secret Manager