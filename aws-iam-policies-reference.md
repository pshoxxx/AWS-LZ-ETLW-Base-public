# IAM Permission Set Policy Reference

Policy ARNs and custom permissions for each IAM Identity Center Permission Set.
Managed by `terraform/management/management_identity_center.tf`.

---

## PlatformAdmin

**AD group:** `aws-iam-engineers` | **Session:** 1h | **Accounts:** management, security, networking, corporate

| Type    | Policy ARN                                      |
|---------|-------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/AdministratorAccess`   |

---

## NetworkAdministrator

**AD group:** `aws-network-admins` | **Session:** 4h | **Accounts:** networking, management

| Type    | Policy ARN                                                       |
|---------|------------------------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/job-function/NetworkAdministrator`      |

---

## SystemAdministrator

**AD group:** `aws-system-admins` | **Session:** 4h | **Accounts:** corporate, management

| Type    | Policy ARN                                                       |
|---------|------------------------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/job-function/SystemAdministrator`       |

---

## DatabaseAdministrator

**AD group:** `aws-database-admins` | **Session:** 4h | **Accounts:** corporate

| Type    | Policy ARN                                                       |
|---------|------------------------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/job-function/DatabaseAdministrator`     |

---

## DataScientist

**AD group:** `aws-data-scientists` | **Session:** 8h | **Accounts:** corporate

| Type    | Policy ARN                                                       |
|---------|------------------------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/job-function/DataScientist`             |

---

## Developer

**AD group:** `aws-developers` | **Session:** 8h | **Accounts:** corporate

| Type    | Policy ARN                                      |
|---------|-------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/PowerUserAccess`        |

---

## SecurityAnalyst

**AD group:** `aws-security-analysts` | **Session:** 8h | **Accounts:** management, security, networking, corporate

| Type    | Policy ARN                                      |
|---------|-------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/SecurityAudit`          |

---

## SecurityEngineer

**AD group:** `aws-security-engineers` | **Session:** 4h | **Accounts:** security, management

| Type   | Permissions                                                                                   |
|--------|-----------------------------------------------------------------------------------------------|
| Inline | `guardduty:*`, `securityhub:*`, `inspector2:*`, `macie2:*`, `access-analyzer:*`              |
| Inline | CloudTrail, Config, IAM, KMS, S3, SNS, CloudWatch read (`Get*`, `List*`, `Describe*`, `FilterLogEvents`, `LookupEvents`, `Select*`) |

---

## DevOps

**AD group:** `aws-devops` | **Session:** 4h | **Accounts:** management, security, networking, corporate

| Type    | Policy ARN / Permissions                                                                      |
|---------|-----------------------------------------------------------------------------------------------|
| Managed | `arn:aws:iam::aws:policy/AmazonEC2FullAccess`                                                 |
| Managed | `arn:aws:iam::aws:policy/AmazonVPCFullAccess`                                                 |
| Managed | `arn:aws:iam::aws:policy/AmazonRDSFullAccess`                                                 |
| Managed | `arn:aws:iam::aws:policy/AWSGlueConsoleFullAccess`                                            |
| Managed | `arn:aws:iam::aws:policy/AmazonGuardDutyFullAccess_v2`                                        |
| Inline  | `cloudfront:*`, `wafv2:*`, `waf-regional:*`                                                   |
| Inline  | `route53:*`, `route53resolver:*`, `route53domains:*`                                          |
| Inline  | `ds:*`, `ssm:*`                                                                               |
| Inline  | `cloudtrail:*`, `logs:*`                                                                      |
| Inline  | `s3:*`                                                                                        |
| Inline  | `kms:Create*`, `kms:Describe*`, `kms:Enable*`, `kms:List*`, `kms:Put*`, `kms:Update*`, `kms:Revoke*`, `kms:Disable*`, `kms:Get*`, `kms:Delete*`, `kms:ScheduleKeyDeletion`, `kms:CancelKeyDeletion`, `kms:CreateGrant` |
| Inline  | IAM service roles: `CreateRole`, `DeleteRole`, `AttachRolePolicy`, `DetachRolePolicy`, `PutRolePolicy`, `DeleteRolePolicy`, `PassRole`, `CreateServiceLinkedRole`, `CreateInstanceProfile`, `DeleteInstanceProfile`, `AddRoleToInstanceProfile`, `RemoveRoleFromInstanceProfile`, `CreatePolicy`, `DeletePolicy` + standard read |
| Inline  | `elasticloadbalancing:*`, EC2/RDS resource tagging                                            |
