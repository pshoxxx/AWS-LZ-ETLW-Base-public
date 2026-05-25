# AWS Landing Zone - Hub and Spoke (ETLW)

This repository implements a production-grade AWS Landing Zone -- a six-account hub-and-spoke architecture covering the spectrum of what a cloud engineer encounters in an enterprise environment: Transit Gateway routing, Network Firewall with stateful inspection, IAM Identity Center backed by AD Connector, a simple web workload spoke that exercises the full inbound (Internet → ALB → PrivateLink → NLB → EC2) and outbound (EC2 → NF egress allowlist → NAT → Internet) chain end to end, and a serverless detection pipeline using Athena, Lambda, and Lake Formation that queries CloudTrail, VPC Flow Logs, and GuardDuty findings from a data lake at storage cost rather than per-event. The entire stack is Terraform, deployed via GitHub Actions CI/CD.

Costs associated with deployment are your own responsibility. This environment is designed to be spun up and torn down on demand, not run continuously.


## Architecture Overview

The landing zone is organized into six AWS accounts under an AWS Organization:

**Management account** -- Organization root, SCPs, CloudTrail org trail, AWS Config delegation, Macie delegation, IAM Identity Center, and AD Connector. No workload resources.

**Networking account** -- Central egress hub. Hosts the Transit Gateway, two AWS Network Firewall instances (one for the ALB ingress path, one for the spoke egress path -- see Network Firewall Architecture below), NAT Gateway, Site-to-Site VPN attachment, and DNS Firewall. All inter-spoke and internet-bound traffic flows through this account.

**Security account** -- Security tooling hub. Hosts GuardDuty, Security Hub, Inspector, Macie, Access Analyzer, the centralized org-logs S3 bucket encrypted with a CMK, and the SIEM (Athena + Lambda + SNS).

**Corporate account** -- Simulated corporate workload spoke. Hosts the corporate VPC, a Windows Server 2025 Domain Controller, and SSM endpoints for management access.

**Shared-services account** -- Infrastructure services account. Hosts the Terraform remote state S3 bucket used by all workspaces. Isolated from workload accounts to prevent accidental state corruption.

**Web account** -- Simulated web workload spoke. Hosts the web VPC, two Amazon Linux 2023 EC2 web servers running a deliberately minimal Python `http.server` bootstrapped from `terraform/web/userdata.sh`, behind an internal NLB. The landing page is a single static asset (`assets/duckling-comic.png`) overlaid with the responding EC2's availability zone fetched from IMDSv2, so refreshing the ALB URL visibly rotates between AZs as the NLB distributes requests. The server is intentionally a one-process Python stdlib HTTP server (no nginx, no app framework, no database tie-in on the request path) so the focus stays on the *routing* the architecture proves and not on the application stack -- swapping in a richer web tier later doesn't change any of the inspection or PrivateLink behavior. Also in this account: Aurora Serverless v2 (provisioned but unused by the demo page), SSM interface endpoints, and a VPC Endpoint Service that publishes the NLB to the networking account via PrivateLink. Inbound traffic flows Internet → IGW → external NF → ALB (networking account) → VPC endpoint → PrivateLink → NLB → EC2. Egress flows EC2 → TGW → internal NF → NAT Gateway → IGW.

The on-premises network is simulated via a pfSense VPN tunnel terminating on the networking account's Site-to-Site VPN attachment to the Transit Gateway. It is a *peer network* reached through the TGW, not a spoke of the architecture itself -- spokes in this design are the AWS VPCs (corporate, web, security, etc.) attached to the TGW. The on-prem Domain Controller runs in VMware Workstation (Windows Server 2025, static IP, bridged networking) and acts as the authoritative identity source for IAM Identity Center via AD Connector.

All spoke VPCs attach to the Transit Gateway in the networking account. Two Network Firewalls split inspection by traffic class (sharing one firewall policy): the **external NF** handles north-south web traffic (Internet ↔ ALB), and the **internal NF** handles east-west and spoke egress (spoke ↔ on-prem via VPN, spoke ↔ spoke, and spoke → NAT → Internet). Each firewall owns its own endpoints in dedicated subnet tiers so stateful inspection is symmetric on every flow without route table conflicts.


## Repository Structure

```
.github/workflows/
    terraform-deploy.yaml     Main deploy pipeline
    terraform-identity.yaml   AD Connector + identity VPC deploy (manual trigger)
    terraform-cleanup.yaml    Destroy pipeline (manual trigger only)

scripts/                            (operational / pipeline-only -- not run by tutorial readers)
    management-import-state.sh       Import management account resources
    security-import-state.sh         Import security account resources
    networking-import-resources.sh   Import individual networking resources
    networking-capture-outputs.sh    Capture networking outputs for downstream use
    phase3-resolve-accounts.sh       Resolve TGW attachment IDs for Phase 3
    phase3-reconcile-vpn.sh          Reconcile VPN configuration in Phase 3
    delegate-administrators.sh       Delegate security service admins
    security-remove-tainted-route53.sh  Remove tainted Route 53 resolver resources

user-scripts/                       (run by tutorial readers and operators)
    domain-controller/
        cloud-dc-promo-prep.ps1            Prep cloud DC for promotion (DNS + MTU + time sync + startup task)
        cloud-dc-promo-replica.ps1         Promote cloud DC as replica in corp.internal
        on-prem-dc-create-groups.ps1       Create Cloud-Access AD groups on the on-prem DC
    queries/
        network-routing-validation.sql     Athena queries for validating the hub-and-spoke routing
    threat-sim/
        siem-threat-simulation.sh          Run 5 reversible threat scenarios for SIEM validation
        siem-threat-simulation-undo.sh     Cleanup for threat simulation

templates/
    management-trust-relationship.json   GitHub-OIDC role trust policy (OIDC provider principal)

terraform/
    bootstrap/      S3 state backend (local state, prevent_destroy)
    management/     Org SCPs, CloudTrail, Config, alarms, Macie, Identity Center, AD Connector
    networking/     TGW, VPN, two Network Firewalls split by traffic class (external for web north-south, internal for east-west + spoke egress), DNS Firewall, egress VPC with split subnet tiers (alb, nat, firewall_external, firewall_internal, tgw_attachment)
    networking-web/ Phase 3 web-ingress workspace -- internet-facing ALB + PrivateLink consumer endpoint in the networking account, deployed after the web account exports the VPC Endpoint Service name
    security/       GuardDuty, Security Hub, KMS CMK, S3 org-logs bucket, SIEM
    corporate/      Corporate VPC, Domain Controller, SSM endpoints
    web/            Web VPC, EC2 web servers (Python http.server bootstrapped from userdata.sh), NLB, Aurora Serverless v2, VPC Endpoint Service (producer)

assets/                         Static assets served by the demo web spoke (duckling-comic.png)
aws-iam-policies-reference.md   IAM Identity Center permission set reference: AD group mappings, managed policy ARNs, and inline policy summaries for all nine permission sets
checkov.yaml                    Checkov security scan suppression config
.gitattributes                  Enforces LF line endings for shell scripts and Terraform files
```


## CI/CD Pipeline

The deploy pipeline runs on push to main. Jobs run in this order:

```
resolve-accounts
    |
security-scan-hcl  (Checkov -- hard-fail gate; findings uploaded to Security tab as SARIF)
    |
deploy-networking
    |
deploy-management-scps
    |
deploy-member-accounts  (security + corporate in parallel)
    |
deploy-web  (waits for deploy-member-accounts so org-logs bucket exists)
    |
deploy-networking-phase3  (TGW route table associations + firewall log delivery + networking-web ALB and PrivateLink consumer endpoint)
    |
deploy-management
```

The cleanup pipeline is manually triggered only. Jobs run as follows: destroy-security, destroy-corporate, and destroy-web run in parallel, then destroy-networking (waits for all three), then destroy-management (only if the destroy_management dispatch input is set to true -- not run by default), then destroy-bootstrap (only if destroy_state_bucket is also set). The networking destroy step retries up to three times and polls AWS for NAT Gateway state (up to 10 minutes) before each attempt, then explicitly releases any unassociated EIPs, so the asynchronous teardown of NAT Gateways and Network Firewall endpoint ENIs does not produce DependencyViolation errors on IGW detach. A best-effort CLI fallback also force-deletes the networking-web ALB if Terraform leaves it behind (which happens when the web-endpoint-service lookup returns empty and the inline workspace destroy silently no-ops). The preserve_domain_controllers dispatch input snapshots DC instances to AMI before destroy so AD configuration survives a teardown and redeploy cycle.

The management account teardown is gated behind an explicit opt-in for two reasons. First, the management account hosts governance resources (SCPs, CloudTrail org trail, Config, IAM Identity Center) that protect all member accounts -- accidental destruction would leave member accounts unguarded and break all federated access. Second, several management resources cannot be fully automated: the AD Connector cannot be deleted while Identity Center has an authorized application registered against it, and service-linked roles for Config and Access Analyzer cannot be deleted while the services themselves are active in the account. The manual gate ensures the operator has disconnected Identity Center from the AD directory before Terraform attempts to destroy the identity stack (see Post-Teardown Manual Cleanup below).

The identity pipeline (terraform-identity.yaml) is triggered manually after DC promotion is complete. It deploys the management identity VPC, TGW attachment, AD Connector security group, and AD Connector into the management account. It is gated by the identity_enabled variable (default false) and requires TF_VAR_AD_CONNECTOR_PASSWORD to be set as a GitHub secret.

A complete end-to-end deployment including SSO assignments takes approximately 3-5 hours assuming prerequisites are in place (AWS accounts created, OIDC role configured, GitHub secrets set, pfSense available). The dominant variable is the IAM Identity Center initial AD sync after connecting the AD Connector -- the first sync cycle completes within 30 minutes to 2 hours ([how configurable AD sync works](https://docs.aws.amazon.com/singlesignon/latest/userguide/how-it-works-configurable-ADsync.html)). The sync scope is a required manual step (no Terraform provider support); see "Configure sync scope" under Known Manual Steps. Everything else on the critical path can be parallelized or prepared in advance. See the Known Manual Steps section for the full sequencing.


## One-Time IAM Setup

Before running any pipeline, create the GitHub Actions OIDC role in the management account. This is a one-time manual step — it cannot be Terraformed because the pipeline needs this role to exist before it can assume anything.

### 1. Add the GitHub OIDC provider

In the management account: IAM -> Identity providers -> Add provider. Select OpenID Connect, set the provider URL to `https://token.actions.githubusercontent.com`, and set the audience to `sts.amazonaws.com`.

### 2. Create the GitHub-OIDC role

IAM -> Roles -> Create role. Select "Custom trust policy" and paste the contents of `templates/management-trust-relationship.json`, replacing the placeholders:

- `YOUR_MANAGEMENT_ACCOUNT_ID` -- the 12-digit management account ID
- `YOUR_GITHUB_ORG/YOUR_REPO_NAME` -- your GitHub repository in `org/repo` format

Attach the `AdministratorAccess` managed policy. Name the role exactly `GitHub-OIDC` (the workflows reference this name directly).

`AdministratorAccess` includes `sts:AssumeRole` on all resources, so no additional inline policy is needed for cross-account access. No changes to the member account trust relationships are required either — accounts created through AWS Organizations already have `OrganizationAccountAccessRole` configured to trust the management account root, which covers any management account principal (including the GitHub-OIDC role).


## Console Access (IAM User)

Create a single IAM user directly in the management account for all console work throughout the deployment — VPN tunnel details, Fleet Manager DC access, and any manual verification steps. This user is also your break-glass credential per AWS Well-Architected SEC03-BP03, usable if IAM Identity Center becomes unavailable.

SCPs attached to the organization root do not apply to the management account, so this user is not subject to the `DenyIAMConsoleLoginProfiles` guardrail that blocks per-account IAM console users in member accounts.

**Cross-account access**: use console role switch to assume `OrganizationAccountAccessRole` in any member account. This role is automatically provisioned in every member account by AWS Organizations and trusts the management account. In the console: click your account name → Switch Role → enter the target account ID and `OrganizationAccountAccessRole`.

Always switch roles from the management account session. Attempting to assume a role while already in a member account session will be interpreted as originating from that member account, which the target account's trust policy will reject.

**Additional users**: create a second IAM user (or one per account using `OrganizationAccountAccessRole`) if you want to test guardrail enforcement — for example, verifying that the `DenyUnencryptedEBSVolumes` SCP returns AccessDenied, or confirming the region restriction blocks API calls to us-east-1. Testing guardrails requires a principal that can actually attempt the blocked action; the primary break-glass user should not be used for destructive or exploratory testing.


## Required GitHub Secrets

```
MANAGEMENT_ACCOUNT_ID               Org management account -- used for OIDC role assumption
TFSTATE_BUCKET_NAME                 Remote state S3 bucket
TF_VAR_ON_PREM_WAN_IP               VPN peer IP for Site-to-Site VPN endpoint

TF_VAR_AD_CONNECTOR_PASSWORD        Domain admin password for AD Connector (identity pipeline only)
```

The security account ID is resolved dynamically at deploy time via the AWS Organizations API (queried by account name). The SIEM alert email is similarly derived from the security account's registered Organizations email. Neither requires a secret.

`TF_VAR_AD_CONNECTOR_PASSWORD` is stored as a GitHub Actions encrypted secret rather than in AWS Secrets Manager. Secrets Manager ($0.40/secret/month) is the right choice when a credential needs rotation, cross-team access, or a centralized audit trail. None of those apply here: the password is consumed exactly once (initial AD Connector creation), the AD Connector resource has `lifecycle { ignore_changes = [password] }` so subsequent applies never re-read it, and the credential is used only by this single workflow. GitHub Secrets is free, already scoped to the repository, and appropriate for a single-workflow secret with no rotation requirement.


## Security Controls

### Service Control Policies

Four SCPs are attached to the organization root and apply to all non-management accounts:

**baseline-guardrails** -- Denies leaving the organization, tampering with CloudTrail, disabling GuardDuty, creating IAM console login profiles, and all root user actions.

**security-service-protection** -- Denies disabling or deleting Security Hub, Config recorders and delivery channels, Macie, Inspector, and Access Analyzer. Complements baseline-guardrails to provide complete coverage across all security services.

**region-restriction-us-west-1** -- Denies API calls outside us-west-1, with exemptions for global services (IAM, Route 53, Organizations, KMS, etc.).

**enforce-ebs-encryption** -- Denies CreateVolume and RunInstances unless the volume is encrypted. Cannot be overridden by member account principals regardless of IAM permissions.

A tag policy enforces key capitalization and allowed values for Environment and ManagedBy. A hard-enforcement variant (deny resource creation without required tags) is present in the file but commented out with instructions, as it is too disruptive for a dev environment.

Note: SCPs attached to the root never apply to the management account by AWS Organizations design. In a production environment, critical resources such as the CloudTrail trail, org-logs S3 bucket, KMS CMK, and GuardDuty detector would also carry lifecycle prevent_destroy = true to prevent accidental removal via Terraform. This environment omits those blocks to allow on-demand teardown.

### Security Scanning (Checkov)

Checkov runs as a pre-deployment stage (security-scan-hcl) against Terraform HCL source. A plan-mode scan also runs within each deploy stage against the resolved plan JSON. Both scans are hard-fail enforcement gates: a FAILED result on any unsuppressed check blocks the pipeline. Findings are uploaded to the GitHub Security tab as SARIF after each run.

The primary artifact is checkov.yaml, which documents 49 intentional deviations with architectural justifications. The rigor lives in the suppression list: each entry was triaged and explained rather than silently skipped. Silent suppressions are not permitted -- all suppressions are reviewed in PRs like any other code change.

The soft-fail-on configuration in checkov.yaml downgrades MEDIUM and LOW severity findings to non-blocking warnings. HIGH and CRITICAL findings that are not suppressed are hard failures. All current HIGH/CRITICAL findings have suppressions with documented justifications in checkov.yaml.

### Network Firewall Architecture (Split by Traffic Class)

The egress VPC runs two Network Firewalls split by **traffic class**, not by direction. Both share the same firewall policy and rule set; the split exists so each class has its own dedicated endpoint per AZ (AWS Network Firewall enforces a one-endpoint-per-AZ-per-firewall limit).

| Firewall                          | Traffic class                                 | Flows handled                                                                                       |
|-----------------------------------|-----------------------------------------------|-----------------------------------------------------------------------------------------------------|
| `hub-network-firewall-external`   | North-south (web)                             | Internet <-> ALB only                                                                               |
| `hub-network-firewall-internal`   | East-west + spoke egress                      | Spoke <-> on-prem (VPN/AD), spoke <-> spoke, spoke -> internet via NAT, internet -> spoke return    |

The internal firewall handles all east-west and spoke-egress traffic: TGW arrives in the egress VPC, `0.0.0.0/0` from the `tgw_attachment` RT goes through the internal NF endpoint, and the internal NF's downstream route table picks the next hop (NAT for internet egress, TGW for spoke / on-prem destinations). The external firewall is purely additive for the web spoke and never sees east-west traffic. The split keeps the AD/VPN-critical east-west path isolated from the web ingress inspection chain so a misconfiguration on one side can't break the other.

Subnet tiers per AZ (x 2 AZs):

| Tier                | CIDR (AZ1 / AZ2)               | Hosts                                              |
|---------------------|--------------------------------|----------------------------------------------------|
| `tgw_attachment`    | 10.0.10.0/28, 10.0.10.16/28    | TGW VPC attachment ENIs                            |
| `firewall_external` | 10.0.10.32/28, 10.0.10.48/28   | External NF endpoints (web north-south only)       |
| `firewall_internal` | 10.0.10.64/28, 10.0.10.80/28   | Internal NF endpoints (east-west + spoke egress)   |
| `alb`               | 10.0.0.0/24, 10.0.1.0/24       | Internet-facing ALB ENIs only                      |
| `nat`               | 10.0.2.0/24, 10.0.3.0/24       | NAT Gateways only                                  |

**Symmetric flow paths:**

- **Internet -> ALB:** IGW -> IGW edge RT (`alb` CIDR -> external NF) -> external NF endpoint -> ALB
- **ALB -> Internet:** ALB -> `alb` RT (`0.0.0.0/0` -> external NF) -> external NF endpoint -> `firewall_external` RT (`0.0.0.0/0` -> IGW) -> IGW (1:1 NAT on ALB public IP)
- **Spoke -> Spoke / On-prem (VPN):** TGW -> `tgw_attachment` RT (`0.0.0.0/0` -> internal NF) -> internal NF endpoint -> `firewall_internal` RT (`<spoke_cidr or on_prem_cidr>` -> TGW) -> TGW -> destination attachment
- **Spoke -> Internet:** TGW -> `tgw_attachment` RT (`0.0.0.0/0` -> internal NF) -> internal NF endpoint -> `firewall_internal` RT (`0.0.0.0/0` -> NAT GW) -> NAT GW (SNAT) -> `nat` RT (`0.0.0.0/0` -> IGW)
- **Internet -> Spoke (return):** IGW -> NAT GW (DNAT) -> `nat` RT (spoke CIDR -> internal NF) -> internal NF endpoint -> `firewall_internal` RT (spoke CIDR -> TGW) -> TGW. The pre-DNAT leg of the return path is NOT routed through the internal NF because the inbound packet's 5-tuple at that point (internet → NAT EIP) wouldn't correlate with the outbound flow NF tracked (web EC2 → internet), causing NF to drop the SYN-ACK as an orphan. Meaningful inspection happens post-DNAT where the spoke IP is visible to the firewall.

Because each flow's request and response traverse the same firewall endpoint, the stateful engine sees both halves of every TCP handshake and connection tracking works correctly.

### Routing Verification

Validation pairs three independent evidence sources, each chosen for the leg it best demonstrates:

| Layer | Evidence source | Where it lives |
|-------|----------------|----------------|
| Hybrid (VPN/AD) leg | `Test-NetConnection -TraceRoute` from on-prem DC to `dc01-corporate` | run from the on-prem DC; output pasted in article |
| Cloud-side per-packet traffic | VPC Flow Logs queried via Athena | `user-scripts/queries/network-routing-validation.sql` against the `org-siem` database in the security account |
| Aggregate hub throughput | CloudWatch dashboard `network-routing-traffic` | security account console; one row per architectural layer (VPN -> TGW -> NF -> NAT -> ALB -> NLB) |

VPC Reachability Analyzer was considered but rejected: per AWS documentation ([Considerations](https://docs.aws.amazon.com/vpc/latest/reachability/what-is-reachability-analyzer.html)), the analyzer "does not evaluate the configuration of components such as load balancers, NAT gateways, Network Firewall, Site-to-Site VPN, and transit gateway peering attachments" -- which means every path in this architecture traverses at least one component the analyzer treats as opaque. Empirical evidence (per-packet VPC flow logs, live CloudWatch metrics, and a `tracert` over the VPN) is both stronger and portable across regions where multi-account analyzer features may not be fully available.

**Athena queries (four core + one optional).** `user-scripts/queries/network-routing-validation.sql` covers: VPN/AD bidirectional traffic, web ingress chain at the ALB ENI, spoke-to-spoke + spoke-to-on-prem flows, and a REJECT scan for silent drops on architecturally-expected internal flows. An optional fifth query is an inference exercise -- it searches NF flow logs for the fingerprint of an egress denial (short TLS-port flow with no successful return), useful for practicing deduction from imperfect data after running the curl deny demo. Each query uses partition projection on the `vpc_flow_logs` Parquet table to keep scans bounded.

**CloudWatch dashboard.** The `network-routing-traffic` dashboard in the security account walks a reader sequentially through the data plane: VPN tunnel state + bytes -> TGW per-attachment bytes -> Network Firewall packet counts -> NAT GW bytes out / connection counts -> ALB request count / 2XX -> NLB processed bytes / active flows. The dashboard uses `SEARCH()` expressions and AWS CloudWatch cross-account observability (OAM sink in security with links from networking, corporate, web) so all metrics surface in one pane regardless of which account hosts the resource. Setup is fully Terraform-managed: the OAM sink lives in `terraform/security/observability.tf`; the OAM links in source accounts are provisioned from `terraform/management/observability_links.tf` via aliased providers (management is the org root and can assume `OrganizationAccountAccessRole` into any member account, so no additional trust policies are required). The NAT Gateway panels (4 / 4b) are deliberately driven by spoke-initiated egress, so to populate them the tutorial directs the reader to run a short `curl` loop from a web EC2 against the egress allowlist's allowed domains -- that same curl loop also produces a paired deny test, which feeds the optional Athena exercise above.

### Egress Allowlist & Alerting Posture

Outbound spoke traffic to the internet is filtered by a TLS_SNI domain allowlist (`var.allowed_egress_domains`, defaults: `.amazonaws.com`, `.github.com`, `.githubusercontent.com`, `.docker.io`, `.docker.com`, `.pypi.org`, `.python.org`, `.fedoraproject.org`, `.example.com`) enforced by the internal Network Firewall. Two non-default configurations are required for the allowlist to function in this hub-and-spoke topology:

- **Firewall policy stateful default = `aws:drop_established`** (not `aws:drop_strict`). The allowlist inspects the TLS Server Name Indication extension, which is only present on the TLS Client Hello *after* the TCP handshake completes. `aws:drop_strict` would drop the initial SYN before the handshake could happen and the allowlist could never evaluate. `aws:drop_established` lets setup packets through so SNI can be inspected; non-matching connections are then dropped at the established-flow layer.
- **`HOME_NET` rule variable on the allowlist rule group** enumerating every spoke CIDR (plus on-prem). The AWS-generated Suricata rules use `$HOME_NET` as the source filter, which defaults to the deploying VPC's CIDR -- here, the egress VPC. Spoke-sourced traffic (10.1/10.2/10.3/10.4.x.x arriving via TGW) wouldn't match without the explicit `HOME_NET` and would fall through the allowlist entirely.

Allowed domains pass silently; non-matching domains are dropped mid-TLS-handshake (visible to the client as a connection that completes TCP, sends the Client Hello, and then times out without a server response). The Network Firewall alert log destination is wired to the security log bucket and a Glue table is provisioned for querying it, but the policy intentionally ships with no rules that emit alerts -- alerting is not enabled in this build, the destination is observability infrastructure ready for explicit alert rules an operator may author later. The reason for that posture (cost, signal-to-noise, and the value of teaching deduction from imperfect data) is covered in the article and in the optional Athena query's comment block.


## Identity and Access Management

### IAM Identity Center with AD Connector

Human access to AWS accounts is managed through IAM Identity Center backed by an on-premises Active Directory via AD Connector. This replaces manually created IAM roles and console passwords across all accounts.

AD Connector was chosen over SCIM-based federation for the following reasons:

- **Single source of truth**: User objects, group memberships, and credentials exist only on the on-premises Domain Controller. No identity data is replicated into AWS.
- **Stateless proxy**: AD Connector does not store any directory data in AWS. It proxies authentication requests through the VPN to the DC at login time. This minimizes the AWS-side attack surface compared to maintaining a synchronized copy of the identity store.
- **No licensing cost**: SCIM federation with a cloud IdP such as Microsoft Entra ID (formerly Azure AD) requires an Entra ID P1 or P2 license per user. AD Connector achieves the same federated login behavior using an existing on-premises AD investment without additional per-user licensing.
- **VPN as an authentication control**: Because AD Connector authenticates against the DC over the VPN tunnel, the VPN being down is an implicit circuit-breaker for human console access. This is desirable in a hub-and-spoke architecture where the VPN represents the trust boundary.

SCIM is appropriate when migrating away from on-premises AD toward a cloud-native IdP. This architecture moves in the opposite direction -- the DC is the enterprise anchor.

### AD Connector Placement: Management Account vs. Delegated Administrator

AWS mandates that the AD Connector (or AWS Managed Microsoft AD) must reside in the same account as IAM Identity Center. That leaves two options:

**Management account** -- the default. IAM Identity Center and the AD Connector coexist in the management account. Simpler to configure, no additional accounts or cross-account policies required.

**Delegated administrator account** -- a separate member account is registered as the IAM Identity Center delegated admin. IAM Identity Center and the AD Connector move into that account. This is the correct pattern at enterprise scale because it avoids concentrating long-lived access in the management account and limits the blast radius of an Identity Center misconfiguration.

This environment uses the management account. IAM Identity Center is joined by SCPs, CloudTrail, Config, and Macie in the management account -- governance is already colocated there by design. Adding a dedicated identity account would require a 5th account, an additional VPC and TGW attachment, delegated-admin registration, and cross-account permission set management. For a single workload spoke, that overhead adds no meaningful security benefit.

Use the delegated administrator pattern when the organization has multiple spokes and teams, when minimizing management account access is a hard requirement, or when the identity function is managed by a separate team from the platform team that controls the management account.

### Multi-Factor Authentication

MFA is enforced through IAM Identity Center's built-in MFA, which sits on top of AD Connector authentication. The flow is: user authenticates with their corp.internal AD password (proxied to the DC), then Identity Center prompts for an MFA code from a registered device. The MFA device (TOTP authenticator app or hardware security key) is registered in Identity Center and is independent of AD.

To enable, go to IAM Identity Center -> Settings -> Multi-factor authentication and set:
- Prompt users for MFA: Always-on
- Allowed MFA types: Authenticator apps and/or security keys
- Who can manage MFA devices: Users can add and manage their own

Users register their device on first login after MFA is enabled. No Terraform changes are required -- this is a console-only setting.

### Alternative: SCIM Federation with an On-Premises DC

In an enterprise environment where a cloud IdP such as Entra ID or Okta is already in use as the authentication broker, the AD Connector can be replaced with a SCIM provisioning connection without any changes to the Terraform permission sets or account assignments. The identity source change is a manual console step in both cases.

The architecture would be:

```
On-prem DC (corp.internal)
    |
    | LDAP sync (Entra ID Connect agent or Okta LDAP agent, installed on DC)
    v
Cloud IdP (Entra ID / Okta / JumpCloud)
    |
    | SCIM 2.0 provisioning (pushes users and groups into Identity Center store)
    v
IAM Identity Center (built-in identity store, SCIM-populated)
    |
    | SAML 2.0 authentication
    v
AWS accounts
```

The on-premises DC remains the authoritative source. The IdP syncs from it periodically via LDAP and provisions changes into the Identity Center built-in store. Authentication happens against the IdP rather than the DC directly.

The VPN still exists for workload traffic (Corporate VPC to on-prem) but is no longer in the authentication path. This removes the VPN-as-circuit-breaker property but allows human console access to remain available if the VPN tunnel is down.

The Terraform permission sets, policy attachments, and account assignments defined in management_identity_center.tf are identical under both models. The aws_identitystore_group data source looks up groups by DisplayName regardless of whether the backing store is AD (via AD Connector) or the built-in store (via SCIM).

Cost note: this pattern requires the IdP to support SCIM provisioning. Entra ID requires a P1 or P2 license per user for automated provisioning. JumpCloud and Okta both offer free tiers suitable for non-production environments.

### Permission Sets

Nine Permission Sets are defined in terraform/management/management_identity_center.tf and map to AD security groups in the Cloud-Access OU on the Domain Controller:

| Permission Set | AD Group | Policy | Accounts |
|---|---|---|---|
| PlatformAdmin | aws-iam-engineers | AdministratorAccess | All six |
| DevOps | aws-devops | Custom composite (EC2/VPC/RDS/Glue/WAF/Route53/DS) | All six |
| SecurityAnalyst | aws-security-analysts | SecurityAudit (read-only) | All six |
| SecurityEngineer | aws-security-engineers | Custom (GuardDuty/SecurityHub/Inspector/Macie/AccessAnalyzer) | Security + Shared-services |
| NetworkAdministrator | aws-network-admins | NetworkAdministrator | Networking only |
| SystemAdministrator | aws-system-admins | SystemAdministrator | Corporate + Management |
| DatabaseAdministrator | aws-database-admins | DatabaseAdministrator | Corporate |
| DataScientist | aws-data-scientists | DataScientist | Corporate |
| Developer | aws-developers | PowerUserAccess | Corporate + Shared-services |

### Deployment Sequence for Identity Center

Identity Center and account assignments are gated behind two Terraform variables that both default to false, preventing accidental deployment before prerequisites are met:

1. Manually enable IAM Identity Center in the management account console.
2. Run terraform-deploy.yaml. Permission Sets, policy attachments, and account assignments are all deployed in this single run.
3. Ensure VPN tunnel is active and DC promotion is complete (see DC Promotion below).
4. Run terraform-identity.yaml to deploy the AD Connector into the management account (takes 20-30 minutes). This workflow provisions: management identity VPC, identity subnets, TGW attachment, AD Connector security group, and the AD Connector directory itself.
5. In the IAM Identity Center console, switch the identity source to the AD directory created in step 4.
6. Wait for the initial AD sync to complete -- the nine Cloud-Access groups must appear in Identity Center before access assignments are active.

The AD groups are created on the Domain Controller by running user-scripts/domain-controller/on-prem-dc-create-groups.ps1 in PowerShell as Administrator on the DC. The script is idempotent and safe to re-run.

### DC Promotion

The corporate DC (dc01-corporate) must be promoted as a replica DC in the corp.internal forest before the AD Connector can authenticate users. Two scripts handle this:

**user-scripts/domain-controller/cloud-dc-promo-prep.ps1** -- Run first. Sets the adapter DNS to the on-prem DC IP (192.168.1.200) so the promotion wizard can resolve corp.internal, and registers a one-shot startup task that resets DNS to 127.0.0.1 after the promotion reboot. The local DNS Server handles corp.internal authoritatively and forwards all other queries to the VPC resolver, keeping SSM Fleet Manager connectivity intact.

**user-scripts/domain-controller/cloud-dc-promo-replica.ps1** -- Run immediately after prep in the same session. Validates prerequisites (hostname applied, AD DS role installed, DNS pointing at on-prem DC), auto-discovers the replication source DC from SRV records, prompts for domain credentials and DSRM password, then runs Install-ADDSDomainController. The server reboots automatically on completion.

Prerequisites:
- **The full deploy pipeline must have completed successfully** -- specifically the `deploy-networking-phase3` job. Phase 3 creates the TGW route table associations that route corporate-spoke traffic to the egress VPC. Without those associations, the corporate DC has no path to the on-prem DC over the VPN, and dcpromo hangs at the replication step with no error output (the SYN packets get silently black-holed at the TGW). Confirm the pipeline summary shows every job green before starting promotion.
- VPN tunnel must be active before running either script
- AD Sites and Services on the on-prem DC must have the AWS site, subnet (10.1.10.0/24), and site link configured before promotion
- Pass -SiteName matching the AWS site name you created in AD Sites and Services
- If redeploying after a previous promotion, ALL stale DC01-CORPORATE metadata must be removed from the on-prem DC first. A failed prior promotion leaves objects in three places: the NTDS Settings server object under CN=Sites, the computer account under either CN=Domain Controllers (if the previous promotion got far enough) or CN=Computers (if it failed during the domain join phase), plus any DFSR replica set entries. Removing only the computer account is not sufficient -- dcpromo's uniqueness check specifically reads the NTDS Settings server object, so an orphan there triggers "A domain controller with the specified name already exists" even when the computer account is gone. Run the full sweep on the on-prem DC as Domain Admin:

  ```powershell
  $staleDc  = "DC01-CORPORATE"
  $serverDN = "CN=$staleDc,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=corp,DC=internal"

  # 1. NTDS Settings server object (the dcpromo uniqueness blocker)
  Get-ADObject -Identity $serverDN -ErrorAction SilentlyContinue |
      Remove-ADObject -Recursive -Confirm:$false

  # 2. Computer account in CN=Domain Controllers OU (if present)
  Get-ADComputer -Identity $staleDc -ErrorAction SilentlyContinue |
      Remove-ADComputer -Confirm:$false

  # 3. Any remaining objects (e.g. computer account left in CN=Computers
  #    from a domain join that preceded a failed promotion, or DFSR entries)
  Get-ADObject -Filter "Name -eq '$staleDc'" -SearchBase "DC=corp,DC=internal" -ErrorAction SilentlyContinue |
      Remove-ADObject -Recursive -Confirm:$false

  # Verify -- should return nothing before re-running promotion
  Get-ADObject -Filter "Name -eq '$staleDc'" -SearchBase "DC=corp,DC=internal"
  ```

After the promotion reboot, allow 5-10 minutes for Windows to initialize AD services, then verify with repadmin /replsummary (should show 0 errors on both source and destination DCs).

Redeployment note: when running the cleanup pipeline with preserve_domain_controllers enabled, an AMI of the DC is saved and tagged before destroy. The next deploy run automatically discovers the most recent tagged AMI and restores the promoted DC state without re-running promotion or any manual input.


## SIEM -- Viewing Alert Data

Traditional SIEMs (Splunk, Microsoft Sentinel, QRadar) charge per GB ingested or per event at ingest time. At scale, ingesting high-volume sources such as VPC Flow Logs or CloudTrail across multiple accounts becomes cost-prohibitive, so organizations either cap retention, sample events, or exclude entire log sources. This is a core limitation of the ingest-based pricing model.

The ETLW (ETL Warehouse) architecture in this repo takes a different approach: all logs land in S3 at storage cost ($0.023/GB-month), Glue catalogs the partitions, and Athena queries only the data relevant to each detection on a 70-minute lookback window. There is no ingest cost. Query cost is bounded by partition pruning regardless of total data volume. This makes it practical to retain and query log sources that would be filtered out of a traditional SIEM purely on cost grounds -- for example, full VPC Flow Log coverage across all spoke VPCs.

The SIEM runs in the security account and uses Athena to query CloudTrail, VPC Flow Logs, and GuardDuty findings stored in the org-logs S3 bucket.

**Where to view results:**

SNS email alert -- an email is sent to the security account's registered AWS Organizations email address whenever the Lambda finds findings in the lookback window. The email summarizes which detections fired and the finding count for each.

Athena console -- go to the security account, open Athena, select the org-siem workgroup and the org-siem database. Run a query directly against any table (e.g. SELECT * FROM cloudtrail LIMIT 10).

CloudWatch metrics -- go to CloudWatch in the security account, open Metrics -> SIEM/Detections. Each detection publishes a metric with the finding count per run.

CloudWatch Logs -- go to CloudWatch -> Log groups -> /aws/lambda/siem-detector. Each Lambda invocation logs which detections ran, how many findings each returned, and any errors.

GitHub Security tab -- Checkov SARIF results are uploaded here after each scan run. Go to the repository -> Security -> Code scanning alerts.

**Manually invoking the Lambda:**

```bash
# Run from CloudShell in the security account.
# --invocation-type Event returns immediately; Lambda runs asynchronously.
# Results arrive via SNS email in approximately 5 minutes.
aws lambda invoke \
  --function-name siem-detector \
  --region us-west-1 \
  --invocation-type Event \
  --cli-binary-format raw-in-base64-out \
  --payload '{"lookback_minutes": 90}' \
  /tmp/siem-response.json
```

**Detection lookback window:**

The Lambda runs hourly and queries the last 70 minutes of data. The 70-minute window provides a 10-minute overlap with the previous run to account for EventBridge scheduling jitter and Lambda cold starts. Queries are bounded to a partition-pruned time window to keep Athena scan costs proportional to the lookback period rather than the full table size.


## Detections

| Detection | Data Source | Maps To |
|---|---|---|
| ConsoleLoginWithoutMFA | CloudTrail | CIS 3.2 |
| RootAccountActivity | CloudTrail | CIS 3.3 |
| IAMPrivilegeEscalation | CloudTrail | AttachRolePolicy/PutRolePolicy with admin ARN |
| UnauthorizedLogBucketAccess | CloudTrail | NIST AU-9 |
| UnencryptedResourceCreation | CloudTrail | EBS/RDS/S3 without encryption |
| SecurityServiceTampering | CloudTrail | NIST SI-7 |
| GuardDutyHighSeverity | GuardDuty findings | Severity >= 7 |
| RejectedSensitivePorts | VPC Flow Logs | External traffic on ports 22/3389/445/1433 |
| CredentialExposure | CloudTrail | Password/secret in request parameters |
| AthenaMaxQuerySeconds | CloudWatch | SIEM health -- query > 60s indicates schema issues |


## Threat Simulation

The user-scripts/threat-sim/siem-threat-simulation.sh script simulates five threat scenarios to validate the SIEM detections end-to-end.

Pre-flight: the EBS encryption SCP and account-level EBS encryption defaults must be temporarily disabled before running Scenario 3. Instructions are in the comments at the top of the script.

**Primary method** -- Log in to the security account via IAM Identity Center as a SecurityEngineer and run the script from CloudShell:

```bash
chmod +x siem-threat-simulation.sh
./siem-threat-simulation.sh
```

**Fallback** -- If CloudShell is unavailable in the security account, assume role from the management account CloudShell:

```bash
SECURITY_ID=$(aws organizations list-accounts \
  --query "Accounts[?contains(Name,'security')].Id" --output text)
CREDS=$(aws sts assume-role \
  --role-arn "arn:aws:iam::${SECURITY_ID}:role/OrganizationAccountAccessRole" \
  --role-session-name siem-sim)
export AWS_ACCESS_KEY_ID=$(echo $CREDS | jq -r .Credentials.AccessKeyId)
export AWS_SECRET_ACCESS_KEY=$(echo $CREDS | jq -r .Credentials.SecretAccessKey)
export AWS_SESSION_TOKEN=$(echo $CREDS | jq -r .Credentials.SessionToken)

chmod +x siem-threat-simulation.sh
./siem-threat-simulation.sh
```

Run a specific scenario only:
```bash
./siem-threat-simulation.sh --scenario 3
```

Wait 5-15 minutes for CloudTrail events to reach the org-logs S3 bucket, then the Lambda will run automatically on its hourly schedule or can be invoked manually as shown above. Run the undo script afterward to remove all created resources and restore security posture.

Scenarios: (1) IAM privilege escalation, (2) unauthorized log bucket access, (3) unencrypted EBS volume, (4) Config recorder stop attempt, (5) credential exposure in SSM parameter path.


## On-Premises Integration

The on-premises environment is simulated using VMware Workstation with a Windows Server 2025 Domain Controller:

- **VM networking**: Bridged adapter set explicitly to the physical NIC (not the VMware virtual NIC) so the VM receives a routable LAN IP.
- **DC static IP**: 192.168.1.200 on the 192.168.1.0/24 network. Required to prevent AD Connector and Route 53 Resolver forwarding rules from breaking if the IP changes.
- **DNS**: The DC uses its own loopback address (127.0.0.1) as its DNS resolver and runs the DNS Server role. DoH is disabled on the NIC. External name resolution is handled via DNS forwarders configured in DNS Manager.
- **Domain**: corp.internal (Windows Server 2016 functional level, required by AD Connector).
- **VPN**: pfSense acts as the VPN peer, routing traffic from the LAN to the AWS networking account VPN attachment via Site-to-Site VPN. IPsec firewall rule: source 10.0.0.0/8, destination 192.168.1.0/24.
- **AD Sites and Services**: AWS site configured with subnet 10.1.10.0/24 (more specific than the on-prem site subnet, so AD longest-prefix matching correctly places dc01-corporate in the AWS site).

Route 53 Resolver forwarding rules for corp.internal are deployed into the **corporate account** (`terraform/corporate/corporate_identity.tf`), not the networking account. The outbound resolver endpoint lives in the corporate VPC and forwards corp.internal queries directly to DC01-CORPORATE (10.1.10.4). It is deployed by terraform-identity.yaml when `identity_enabled=true`.

The AWS-recommended pattern for multi-spoke environments is to centralize the resolver endpoint in the networking (hub) account and RAM-share the forwarding rule to each spoke VPC. This eliminates duplicate resolver infrastructure as spokes are added. For this environment with a single workload spoke, that overhead adds no benefit -- the DC is already in the corporate VPC, so the DNS query never leaves the account. If additional spoke accounts are added in the future, the resolver should be migrated to the networking account and the rule shared via RAM.


## Billing Setup (Manual Steps)

Cost data is not automatically configured. Complete these steps after initial deployment:

**1. Activate IAM billing access**
Log in as the root user of the management account. Go to Account -> scroll to "IAM user and role access to Billing information" -> Activate. This must be done as root and is required before any IAM role can view billing data.

**2. Enable Cost Explorer**
In the management account go to Billing and Cost Management -> Cost Explorer -> Enable. Data takes up to 24 hours to populate on first enable.

**3. Create a Budget**
Go to Billing -> Budgets -> Create budget. Set a fixed monthly budget with email alerts at 75%, 90%, and 100% of your threshold.

**4. Activate cost allocation tags**
Go to Billing -> Cost allocation tags. Search for Environment and ManagedBy and activate both.

**5. Verify consolidated billing**
Go to AWS Organizations -> Settings. Confirm feature set shows "All features enabled" which includes consolidated billing.


## Known Manual Steps

Steps are grouped by when they are performed. Terraform-managed resources are noted where applicable.

### After initial deploy (terraform-deploy.yaml)

- **EC2 Serial Console** -- enable on the corporate account before attempting DC promotion, as a break-glass option if SSM loses connectivity. EC2 console -> EC2 Dashboard -> Account attributes -> EC2 Serial Console -> Allow. Can also be enabled via CLI: aws ec2 enable-serial-console-access --region us-west-1 (run as the corporate account).
- **IAM Identity Center** -- enable manually in the management account console. Terraform cannot enable it; the console toggle must be flipped first before any Identity Center resources can be deployed.
- **pfSense VPN tunnel configuration** -- configure the Site-to-Site VPN tunnel on pfSense using the VPN endpoint details from the networking account Terraform outputs.
- **IAM billing access** -- activate as root user in the management account (see Billing Setup above).
- **Per-account alternate contacts** -- set security, billing, and operations contacts per account in the AWS console.

### DC promotion (manual, after the full pipeline completes and the VPN tunnel is up)

- **Run user-scripts/domain-controller/cloud-dc-promo-prep.ps1** on dc01-corporate via SSM Fleet Manager. Sets adapter DNS to the on-prem DC and registers a startup task to reset it after the promotion reboot.
- **Run user-scripts/domain-controller/cloud-dc-promo-replica.ps1** in the same session. Promotes dc01-corporate as a replica DC in corp.internal and reboots. See the DC Promotion section above for full prerequisites.
- **Run user-scripts/domain-controller/on-prem-dc-create-groups.ps1** on the on-prem DC after promotion converges. Creates the Cloud-Access OU and nine IAM Identity Center AD groups on the on-prem DC (the script targets the local AD; running it on the cloud replica works after sync but the on-prem DC is the authoritative source).
- **Set email on AD users** -- when creating users in ADUC, the **Email** field on the General tab must be populated (e.g. `username@corp.internal`). Identity Center uses this attribute to resolve the user identity against account assignments. Without it, the user authenticates successfully via AD Connector but gets "No access" on every account -- the assignments exist but Identity Center cannot match the session to the user record.

### After terraform-identity.yaml

This workflow provisions the management identity VPC, TGW attachment, AD Connector security group, and AD Connector directory.

- **Connect identity source** -- in the IAM Identity Center console, switch the identity source to the AD directory created by the workflow.
- **Configure sync scope (required manual step)** -- in IAM Identity Center -> Settings -> Identity source -> Manage sync -> Groups tab, add all nine Cloud-Access groups (aws-iam-engineers, aws-network-admins, aws-system-admins, aws-database-admins, aws-data-scientists, aws-developers, aws-security-analysts, aws-security-engineers, aws-devops). The Terraform AWS provider and the aws-ia/iam-identity-center module do not expose a resource for sync scope, so this can't be automated today. Initial sync typically completes in 30 minutes to 2 hours after the scope is populated; see [how configurable AD sync works](https://docs.aws.amazon.com/singlesignon/latest/userguide/how-it-works-configurable-ADsync.html).
- **Enable MFA** -- in IAM Identity Center -> Settings -> Multi-factor authentication, configure the following. This is a console-only step; the Terraform AWS provider has no resource for Identity Center MFA prompt settings, and the aws-ia/iam-identity-center community module ([registry.terraform.io/modules/aws-ia/iam-identity-center/aws/latest](https://registry.terraform.io/modules/aws-ia/iam-identity-center/aws/latest)) similarly omits it. The setting is instance-level and applied once -- it does not drift because nothing else touches it.
  - Prompt users for MFA: Always-on
  - Allowed MFA types: Authenticator app, Security key (FIDO2)
  - MFA device management: Users can add and manage their own devices
  Users complete device registration on their first login to the AWS access portal.
- **Wait for AD sync** -- after connecting the identity source, IAM Identity Center performs an initial sync of all AD users and groups. The first sync cycle completes within 30 minutes to 2 hours; see [how configurable AD sync works](https://docs.aws.amazon.com/singlesignon/latest/userguide/how-it-works-configurable-ADsync.html). Groups will not appear in Identity Center -> Groups until sync completes. Do not proceed to the next step until the nine Cloud-Access groups are visible.
- **Verify assignments are active** -- once the nine Cloud-Access groups appear in Identity Center, account assignments created by terraform-deploy are live. Users can now log in via the AWS access portal.

### After teardown (terraform-cleanup.yaml)

The cleanup pipeline destroys all Terraform-managed resources but cannot remove the identity VPC or AD Connector because AWS blocks directory deletion while IAM Identity Center has an authorized application registered against it. These resources must be removed manually after every teardown that includes an active AD Connector.

**Step 1 -- Disconnect Identity Center from the AD directory**

In the management account: IAM Identity Center -> Settings -> Identity source -> Actions -> Change identity source. Select "Identity Center directory" and confirm. This removes the authorized application from the AD Connector and unblocks directory deletion.

**Step 2 -- Delete the AD Connector**

AWS Console -> Directory Service -> select the AD Connector directory -> Actions -> Delete. The directory and its ENIs are deleted automatically; this takes 5-10 minutes.

**Step 3 -- Delete the identity VPC**

After the directory is deleted, the identity VPC and subnets can be removed. AWS Console -> VPC -> Your VPCs -> select the management-identity-vpc -> Actions -> Delete VPC. AWS will also delete the associated subnets and route tables.

**KMS CMK -- schedule for deletion if not redeploying**

The org-logs CMK has `lifecycle { prevent_destroy = true }`, so the cleanup pipeline removes it from Terraform state rather than deleting it. The key remains in the security account and continues to accrue the $1/month KMS key charge. If you plan to redeploy, leave it -- the deploy pipeline re-imports it by alias automatically. If you are done with the environment, go to KMS in the security account, select the org-logs-cmk key, and schedule deletion. AWS enforces a minimum 7-day waiting period before the key is destroyed (this resource has a 30-day window configured).

