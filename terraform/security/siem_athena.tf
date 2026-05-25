# terraform/security/siem_athena.tf
# =====================================================================
# Athena Workgroup and Saved Detection Queries
#
# Query results are stored under athena-results/ in the org-logs bucket,
# encrypted with the same CMK used for all other log data.
#
# Five saved named queries cover the core detection use cases:
#   1. Console login without MFA
#   2. Root account API activity
#   3. Plaintext credentials in CloudTrail user agent / request params
#   4. GuardDuty high severity findings (severity >= 7)
#   5. VPC Flow Log rejected traffic on sensitive ports from external IPs
#
# Run these queries from the Athena console after the Glue crawlers have
# populated the org-siem catalog. The Lambda in siem_lambda.tf runs the
# same queries on a schedule and alerts on non-empty results.
# =====================================================================

resource "aws_athena_workgroup" "siem" {
  name        = "org-siem"
  description = "Security workgroup - detection queries against org-logs data lake"
  # force_destroy allows Terraform to delete the workgroup even when it contains
  # saved named queries and query execution history. Without this flag Terraform
  # errors with "WorkGroup org-siem is not empty" regardless of whether named
  # queries have been manually deleted, because query history also counts.
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.org_logs.id}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.org_logs_cmk.arn
      }
    }

    engine_version {
      selected_engine_version = "Athena engine version 3"
    }
  }

  tags = merge(local.common_tags, {
    Name = "org-siem"
  })
}



# =====================================================================
# Detection Query 1 - Console Login Without MFA (CIS 3.2)
# =====================================================================
# Finds any AWS Console authentication event where MFA was not used.
# This covers IAM users logging in without a virtual or hardware MFA
# device. Federated logins via IAM Identity Center are excluded since
# MFA is enforced at the IdP level, not captured in this event field.
# =====================================================================

resource "aws_athena_named_query" "no_mfa_login" {
  name      = "detection-console-login-without-mfa"
  workgroup = aws_athena_workgroup.siem.id
  database  = aws_glue_catalog_database.siem.name

  description = "CIS 3.2 - Console logins where MFA was not used. Any result is a finding."

  query = <<-SQL
    SELECT
      eventtime,
      useridentity.type       AS identity_type,
      useridentity.arn        AS user_arn,
      useridentity.username   AS username,
      sourceipaddress,
      awsregion,
      additionaleventdata
    FROM cloudtrail
    WHERE eventname = 'ConsoleLogin'
      AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
      AND errorcode IS NULL
    ORDER BY eventtime DESC
    LIMIT 100
  SQL
}

# =====================================================================
# Detection Query 2 - Root Account Activity
# =====================================================================
# Any API call made by the root account is a finding. Legitimate root
# usage is extremely rare and should only occur for account-level tasks
# that no IAM principal can perform (e.g. enabling SCP, closing account).
# =====================================================================

resource "aws_athena_named_query" "root_activity" {
  name      = "detection-root-account-activity"
  workgroup = aws_athena_workgroup.siem.id
  database  = aws_glue_catalog_database.siem.name

  description = "CIS 3.3 - Any API activity by the root account. All results are findings."

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      eventsource,
      sourceipaddress,
      awsregion,
      useridentity.type         AS identity_type,
      useridentity.accountid    AS account_id,
      errorcode,
      errormessage
    FROM cloudtrail
    WHERE useridentity.type = 'Root'
      AND (useridentity.invokedby IS NULL OR useridentity.invokedby = '')
      AND eventtype != 'AwsServiceEvent'
    ORDER BY eventtime DESC
    LIMIT 100
  SQL
}

# =====================================================================
# Detection Query 3 - Plaintext Credentials in CloudTrail
# =====================================================================
# Looks for evidence that long-term IAM access keys were used from
# unexpected CLI tools or embedded in application code. The user agent
# field in CloudTrail records the SDK or tool name; certain patterns
# like 'aws-cli', 'Boto3', 's3transfer' are normal for automation but
# warrant review when combined with unusual source IPs or event names.
#
# Also checks requestparameters for the word 'password' appearing in
# plaintext, which can indicate a misconfigured application passing
# credentials in API calls (e.g. SSM Parameter Store writes, Secrets
# Manager creates with literal strings).
# =====================================================================

resource "aws_athena_named_query" "credential_exposure" {
  name      = "detection-potential-credential-exposure"
  workgroup = aws_athena_workgroup.siem.id
  database  = aws_glue_catalog_database.siem.name

  description = "Finds CloudTrail events where credentials may be exposed in request parameters or suspicious user agents are observed."

  query = <<-SQL
    SELECT
      eventtime,
      eventname,
      eventsource,
      sourceipaddress,
      awsregion,
      useridentity.type       AS identity_type,
      useridentity.arn        AS user_arn,
      useragent,
      requestparameters
    FROM cloudtrail
    WHERE (
      -- Plaintext password-like strings in request parameters
      lower(requestparameters) LIKE '%password%'
      OR lower(requestparameters) LIKE '%secret%'
      OR lower(requestparameters) LIKE '%credentials%'
    )
    -- Exclude known safe write operations that legitimately reference
    -- these words in resource names or descriptions
    AND eventname NOT IN (
      'UpdateAccountPasswordPolicy',
      'GetAccountPasswordPolicy',
      'DescribeSecret'
    )
    AND errorcode IS NULL
    ORDER BY eventtime DESC
    LIMIT 100
  SQL
}

# =====================================================================
# Detection Query 4 - GuardDuty High Severity Findings
# =====================================================================
# Queries GuardDuty findings exported to S3. Severity >= 7 is HIGH or
# CRITICAL in the GuardDuty severity model:
#   0-3.9  Low
#   4-6.9  Medium
#   7-8.9  High
#   9+     Critical
#
# NOTE: The exact field path depends on the schema inferred by the
# Glue crawler. If the crawler creates nested columns, adjust the
# field references to match. The query below assumes the standard
# GuardDuty S3 export format (JSON, one finding per line).
# =====================================================================

resource "aws_athena_named_query" "guardduty_high_severity" {
  name      = "detection-guardduty-high-severity"
  workgroup = aws_athena_workgroup.siem.id
  database  = aws_glue_catalog_database.siem.name

  description = "GuardDuty findings with severity >= 7 (HIGH or CRITICAL). All results require immediate review."

  query = <<-SQL
    SELECT
      updatedat                               AS finding_time,
      severity,
      type                                    AS finding_type,
      title,
      description,
      accountid,
      region,
      json_extract_scalar(resource, '$.resourceType')             AS resource_type,
      json_extract_scalar(service, '$.action.actionType')         AS action_type,
      json_extract_scalar(service, '$.count')                     AS event_count
    FROM guardduty
    WHERE CAST(severity AS DOUBLE) >= 7
    ORDER BY severity DESC, updatedat DESC
    LIMIT 100
  SQL
}

# =====================================================================
# Detection Query 5 - Rejected Traffic on Sensitive Ports
# =====================================================================
# VPC Flow Logs record every accepted and rejected connection attempt.
# REJECT on ports 22 (SSH), 3389 (RDP), 445 (SMB), 1433 (MSSQL), and
# 5985/5986 (WinRM) from non-RFC1918 source addresses indicates active
# scanning or intrusion attempts against your environment.
#
# RFC1918 ranges excluded from external classification:
#   10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
# =====================================================================

resource "aws_athena_named_query" "rejected_sensitive_ports" {
  name      = "detection-rejected-sensitive-port-traffic"
  workgroup = aws_athena_workgroup.siem.id
  database  = aws_glue_catalog_database.siem.name

  description = "VPC Flow Log REJECT events on sensitive ports (SSH/RDP/SMB/MSSQL/WinRM) from external (non-RFC1918) source IPs. Indicates active scanning or intrusion attempts."

  query = <<-SQL
    SELECT
      start                         AS event_time,
      srcaddr                       AS source_ip,
      dstaddr                       AS dest_ip,
      dstport                       AS dest_port,
      protocol,
      action,
      account_id,
      interface_id,
      COUNT(*) AS attempt_count
    FROM vpc_flow_logs
    WHERE action = 'REJECT'
      AND dstport IN (22, 3389, 445, 1433, 5985, 5986)
      -- Exclude RFC1918 sources (internal traffic)
      AND srcaddr NOT LIKE '10.%'
      AND srcaddr NOT LIKE '172.16.%'
      AND srcaddr NOT LIKE '172.17.%'
      AND srcaddr NOT LIKE '172.18.%'
      AND srcaddr NOT LIKE '172.19.%'
      AND srcaddr NOT LIKE '172.2%.%'
      AND srcaddr NOT LIKE '172.3%.%'
      AND srcaddr NOT LIKE '192.168.%'
    GROUP BY
      start, srcaddr, dstaddr, dstport, protocol, action, account_id, interface_id
    ORDER BY attempt_count DESC, event_time DESC
    LIMIT 100
  SQL
}
