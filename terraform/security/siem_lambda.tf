# terraform/security/siem_lambda.tf
# =====================================================================
# SIEM Detection Lambda
#
# Runs all five Athena detection queries and publishes findings to SNS
# when any query returns results. CloudWatch Metrics track query
# execution and finding counts for dashboarding.
#
# Trigger options:
#   - Manual: invoke from Lambda console or AWS CLI
#   - Scheduled: EventBridge rule runs every 15 minutes (disabled by
#     default to avoid cost when the environment is not active - enable
#     from the EventBridge console or by setting var.siem_schedule_enabled)
#
# Alert flow:
#   Lambda -> CloudWatch custom metrics -> CloudWatch Alarm -> SNS -> Email
#   Lambda -> SNS (direct publish for immediate findings)
# =====================================================================

# -- SNS Topic --------------------------------------------------------

resource "aws_sns_topic" "siem_alerts" {
  name              = "siem-security-alerts"
  kms_master_key_id = aws_kms_key.org_logs_cmk.arn

  tags = merge(local.common_tags, {
    Name = "siem-security-alerts"
  })
}

resource "aws_sns_topic_policy" "siem_alerts" {
  arn = aws_sns_topic.siem_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowLambdaPublish"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.siem_alerts.arn
        Condition = {
          ArnLike = {
            "aws:SourceArn" = aws_lambda_function.siem_detector.arn
          }
        }
      },
      {
        Sid    = "AllowCloudWatchPublish"
        Effect = "Allow"
        Principal = {
          Service = "cloudwatch.amazonaws.com"
        }
        Action   = "sns:Publish"
        Resource = aws_sns_topic.siem_alerts.arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
    ]
  })
}

resource "aws_sns_topic_subscription" "siem_email" {
  count     = var.siem_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.siem_alerts.arn
  protocol  = "email"
  endpoint  = var.siem_alert_email
}

# -- Lambda IAM Role --------------------------------------------------

resource "aws_iam_role" "siem_lambda" {
  name = "siem-detector-lambda-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "siem_lambda_basic" {
  role       = aws_iam_role.siem_lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "siem_lambda_permissions" {
  name = "siem-detector-permissions"
  role = aws_iam_role.siem_lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AthenaRun"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
        ]
        Resource = aws_athena_workgroup.siem.arn
      },
      {
        Sid    = "GlueAccess"
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetTables",
          "glue:GetDatabase",
          "glue:GetPartitions",
          "glue:BatchCreatePartition",
          "glue:CreatePartition",
        ]
        Resource = [
          "arn:aws:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:catalog",
          "arn:aws:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:database/${aws_glue_catalog_database.siem.name}",
          "arn:aws:glue:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:table/${aws_glue_catalog_database.siem.name}/*",
        ]
      },
      {
        Sid    = "S3ReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation",
        ]
        Resource = [
          aws_s3_bucket.org_logs.arn,
          "${aws_s3_bucket.org_logs.arn}/*",
        ]
      },
      {
        # Scoped to all CMKs in the security account rather than a specific
        # key ARN to avoid mismatches between the Terraform-managed key and
        # keys that encrypted objects before the import. Each key's own key
        # policy still gates access -- the Lambda can only decrypt objects
        # whose key policy explicitly allows this role.
        Sid    = "KMS"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey",
          "kms:DescribeKey",
        ]
        Resource = ["arn:aws:kms:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:key/*"]
      },
      {
        Sid      = "SNSPublish"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = [aws_sns_topic.siem_alerts.arn]
      },
      {
        Sid    = "CloudWatchMetrics"
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "cloudwatch:GetMetricStatistics",
        ]
        Resource = "*"
      },
    ]
  })
}

# -- Lambda Function --------------------------------------------------

data "archive_file" "siem_detector" {
  type        = "zip"
  output_path = "/tmp/siem_detector.zip"

  source {
    filename = "detector.py"
    content  = <<-PYTHON
import boto3
import datetime
import os
import time

athena  = boto3.client('athena')
sns     = boto3.client('sns')
cw      = boto3.client('cloudwatch')

WORKGROUP   = os.environ['ATHENA_WORKGROUP']
DATABASE    = os.environ['GLUE_DATABASE']
RESULTS_LOC = os.environ['RESULTS_LOCATION']
SNS_ARN     = os.environ['SNS_TOPIC_ARN']
REGION      = os.environ['AWS_REGION']

# Default lookback in minutes. Override at runtime by passing
# {"lookback_minutes": N} in the Lambda event payload -- e.g.
# {"lookback_minutes": 90} after a threat simulation to cover the full
# window from sim start through CloudTrail delivery and Lambda runtime.
# WHY 70: hourly schedule + 10-min overlap buffer so no events fall
# through the gap between runs due to cold start or EventBridge jitter.
DEFAULT_LOOKBACK = 70

# Maps detection names to simulation scenario labels for SNS alerts.
SIMULATION_SCENARIOS = {
    'IAMPrivilegeEscalation':      'Sim Scenario 1 — IAM Privilege Escalation',
    'UnauthorizedLogBucketAccess': 'Sim Scenario 2 — Unauthorized org-logs Access',
    'UnencryptedResourceCreation': 'Sim Scenario 3 — Unencrypted EBS Volume',
    'SecurityServiceTampering':    'Sim Scenario 4 — Security Service Tampering',
    'CredentialExposure':          'Sim Scenario 5 — Credential Exposure in SSM',
}

# Tables using Hive-style partitions that need MSCK REPAIR TABLE before
# querying. New S3 partitions are invisible to Athena until registered.
PARTITIONED_TABLES = ['vpc_flow_logs']

# Tables to probe in the health check (SELECT 1 LIMIT 1).
PROBE_TABLES = ['cloudtrail', 'vpc_flow_logs', 'guardduty']

# Each detection SQL uses {lookback} substituted at runtime.
# The time bound is critical for cost -- without it Athena scans the
# full CloudTrail/flow log table on every invocation.
DETECTIONS = {

    # ----------------------------------------------------------------
    # 1. Console login without MFA (CIS 3.2)
    # ----------------------------------------------------------------
    'ConsoleLoginWithoutMFA': """
        SELECT eventtime, useridentity.type AS identity_type,
               useridentity.arn AS user_arn, sourceipaddress
        FROM cloudtrail
        WHERE eventname = 'ConsoleLogin'
          AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No'
          AND errorcode IS NULL
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 2. Root account activity (CIS 3.3)
    # ----------------------------------------------------------------
    'RootAccountActivity': """
        SELECT eventtime, eventname, eventsource, sourceipaddress,
               useridentity.accountid AS account_id, errorcode
        FROM cloudtrail
        WHERE useridentity.type = 'Root'
          AND (useridentity.invokedby IS NULL OR useridentity.invokedby = '')
          AND eventtype != 'AwsServiceEvent'
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 3. IAM privilege escalation
    # Catches attempts to attach broad policies or inline policies
    # with wildcard actions -- key lateral movement indicator.
    # ----------------------------------------------------------------
    'IAMPrivilegeEscalation': """
        SELECT eventtime, eventname, eventsource,
               useridentity.arn AS actor_arn,
               sourceipaddress,
               requestparameters
        FROM cloudtrail
        WHERE eventsource = 'iam.amazonaws.com'
          AND eventname IN (
              'AttachRolePolicy',
              'AttachUserPolicy',
              'AttachGroupPolicy',
              'PutRolePolicy',
              'PutUserPolicy',
              'PutGroupPolicy',
              'CreatePolicy',
              'CreatePolicyVersion',
              'SetDefaultPolicyVersion'
          )
          AND (
              lower(requestparameters) LIKE '%%"action":"*"%%'
              OR lower(requestparameters) LIKE '%%arn:aws:iam::aws:policy/administratoraccess%%'
              OR lower(requestparameters) LIKE '%%arn:aws:iam::aws:policy/iamfullaccess%%'
          )
          AND errorcode IS NULL
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 4. Unauthorized access to org-logs audit bucket (NIST AU-9)
    # Any read or delete on the log bucket from a principal that is
    # not a known log delivery service is a potential evidence tampering
    # or exfiltration attempt.
    # ----------------------------------------------------------------
    'UnauthorizedLogBucketAccess': """
        SELECT eventtime, eventname,
               useridentity.arn AS actor_arn,
               useridentity.type AS identity_type,
               sourceipaddress,
               requestparameters
        FROM cloudtrail
        WHERE eventsource = 's3.amazonaws.com'
          AND eventname IN ('GetObject', 'DeleteObject', 'DeleteBucket',
                            'PutBucketPolicy', 'DeleteBucketPolicy',
                            'GetBucketPolicy', 'GetBucketAcl', 'ListBucket',
                            'ListObjects', 'ListObjectsV2')
          AND requestparameters LIKE '%%org-logs-%%'
          AND useridentity.type NOT IN ('AWSService')
          AND (useridentity.invokedby IS NULL
               OR useridentity.invokedby NOT IN (
                   'cloudtrail.amazonaws.com',
                   'config.amazonaws.com',
                   'delivery.logs.amazonaws.com',
                   'guardduty.amazonaws.com'
               ))
          AND errorcode IS NULL
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 5. Unencrypted resource creation
    # Detects EC2 volumes, S3 buckets, or RDS instances created
    # without encryption -- monitors encryption posture org-wide.
    # ----------------------------------------------------------------
    # errorcode IS NULL intentionally omitted for this detection.
    # A denied attempt (errorcode = AccessDenied via SCP) is still a
    # finding worth alerting on -- it means someone or something tried
    # to create an unencrypted resource. Catching the attempt is more
    # valuable than catching only successful creations since the SCP
    # prevents success but the intent is still a policy violation.
    'UnencryptedResourceCreation': """
        SELECT eventtime, eventname, eventsource,
               useridentity.arn AS actor_arn,
               awsregion, requestparameters,
               errorcode, errormessage
        FROM cloudtrail
        WHERE (
            (eventname = 'CreateVolume'
             AND (requestparameters NOT LIKE '%%"encrypted":true%%'))
            OR
            (eventname = 'CreateBucket'
             AND eventsource = 's3.amazonaws.com')
            OR
            (eventname = 'CreateDBInstance'
             AND requestparameters NOT LIKE '%%"storageEncrypted":true%%')
        )
          AND useridentity.type != 'AWSService'
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 6. Security service tampering (NIST SI-7)
    # Attempts to disable GuardDuty, Config, Security Hub, or Access
    # Analyzer. SCPs block most of these but detection catches attempts
    # and any gaps in SCP coverage.
    # ----------------------------------------------------------------
    'SecurityServiceTampering': """
        SELECT eventtime, eventname, eventsource,
               useridentity.arn AS actor_arn,
               sourceipaddress, errorcode, errormessage
        FROM cloudtrail
        WHERE eventname IN (
            'DeleteDetector', 'DisassociateFromMasterAccount',
            'StopMonitoringMembers', 'DeleteMembers',
            'StopConfigurationRecorder', 'DeleteConfigurationRecorder',
            'DeleteDeliveryChannel',
            'DisableSecurityHub', 'DeleteHub',
            'DeleteAnalyzer',
            'DisableMacie', 'DisassociateFromAdministratorAccount'
        )
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 7. GuardDuty high severity findings (severity >= 7)
    # Uses updatedat rather than a CloudTrail eventtime -- GuardDuty
    # findings are written to the guardduty Glue table directly.
    # ----------------------------------------------------------------
    'GuardDutyHighSeverity': """
        SELECT updatedat AS finding_time, severity, type AS finding_type,
               title, accountid, region
        FROM guardduty
        WHERE CAST(severity AS DOUBLE) >= 7
          AND updatedat > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY severity DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 8. Rejected traffic on sensitive ports from external IPs
    # Uses start (Unix epoch seconds) from vpc_flow_logs table.
    # from_unixtime converts to timestamp for interval comparison.
    # ----------------------------------------------------------------
    'RejectedSensitivePorts': """
        SELECT from_unixtime(start) AS event_time, srcaddr, dstaddr, dstport,
               action, account_id, COUNT(*) AS attempt_count
        FROM vpc_flow_logs
        WHERE action = 'REJECT'
          AND dstport IN (22, 3389, 445, 1433, 5985, 5986)
          AND srcaddr NOT LIKE '10.%%'
          AND srcaddr NOT LIKE '172.16.%%'
          AND srcaddr NOT LIKE '192.168.%%'
          AND from_unixtime(start) > (current_timestamp - interval '{lookback}' minute)
        GROUP BY start, srcaddr, dstaddr, dstport, action, account_id
        ORDER BY attempt_count DESC LIMIT 20
    """,

    # ----------------------------------------------------------------
    # 9. Credential exposure in request parameters
    # ----------------------------------------------------------------
    'CredentialExposure': """
        SELECT eventtime, eventname, eventsource, sourceipaddress,
               useridentity.arn AS user_arn, useragent
        FROM cloudtrail
        WHERE (lower(requestparameters) LIKE '%%password%%'
               OR lower(requestparameters) LIKE '%%secret%%')
          AND eventname NOT IN ('UpdateAccountPasswordPolicy',
                                'GetAccountPasswordPolicy','DescribeSecret')
          AND errorcode IS NULL
          AND eventtime > to_iso8601(current_timestamp - interval '{lookback}' minute)
        ORDER BY eventtime DESC LIMIT 20
    """,
}

def _poll_query(qid, timeout_sec=300):
    """Poll Athena until the query reaches a terminal state. Returns state string."""
    deadline = time.time() + timeout_sec
    while time.time() < deadline:
        time.sleep(5)
        status = athena.get_query_execution(QueryExecutionId=qid)
        state = status['QueryExecution']['Status']['State']
        if state not in ('RUNNING', 'QUEUED'):
            return state
    return 'TIMEOUT'

def run_query(name, sql):
    """Start an Athena query and poll until complete.
    Returns list of result rows on SUCCEEDED (empty list = no data, still OK),
    or None on FAILED/CANCELLED/TIMEOUT."""
    resp = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={'Database': DATABASE},
        WorkGroup=WORKGROUP,
        ResultConfiguration={'OutputLocation': RESULTS_LOC},
    )
    qid = resp['QueryExecutionId']
    state = _poll_query(qid)
    if state != 'SUCCEEDED':
        try:
            status = athena.get_query_execution(QueryExecutionId=qid)
            reason = status['QueryExecution']['Status'].get('StateChangeReason', '')
        except Exception:
            reason = ''
        print(f"Query {name} {state}: {reason}")
        return None

    results = athena.get_query_results(QueryExecutionId=qid)
    rows = results.get('ResultSet', {}).get('Rows', [])
    return rows[1:] if len(rows) > 1 else []

def repair_partitions():
    """Run MSCK REPAIR TABLE for each partitioned table to register
    newly-delivered S3 prefixes in the Glue catalog."""
    for table in PARTITIONED_TABLES:
        print(f"Repairing partitions: {table}")
        resp = athena.start_query_execution(
            QueryString=f"MSCK REPAIR TABLE {table}",
            QueryExecutionContext={'Database': DATABASE},
            WorkGroup=WORKGROUP,
            ResultConfiguration={'OutputLocation': RESULTS_LOC},
        )
        state = _poll_query(resp['QueryExecutionId'])
        print(f"  {table}: repair {state}")

def check_table_health():
    """Probe each table with SELECT 1 LIMIT 1.
    Returns dict: table_name -> True (accessible) or None (broken/missing)."""
    health = {}
    for table in PROBE_TABLES:
        rows = run_query(f'health_{table}', f'SELECT 1 FROM {table} LIMIT 1')
        health[table] = None if rows is None else True
    return health

def publish_metric(name, count):
    cw.put_metric_data(
        Namespace='SIEM/Detections',
        MetricData=[{
            'MetricName': name,
            'Value': count,
            'Unit': 'Count',
        }]
    )

def handler(event, context):
    lookback = int(event.get('lookback_minutes', DEFAULT_LOOKBACK))
    all_findings = {}
    query_errors = []
    total = 0

    try:
        repair_partitions()
    except Exception as e:
        print(f"Partition repair error: {e}")

    try:
        health = check_table_health()
        broken = [t for t, v in health.items() if v is None]
        if broken:
            print(f"WARNING: unhealthy tables: {broken}")
    except Exception as e:
        print(f"Table health check error: {e}")

    for name, sql in DETECTIONS.items():
        print(f"Running detection: {name}")
        try:
            rows = run_query(name, sql.format(lookback=lookback))
            if rows is None:
                print(f"  {name}: QUERY FAILED")
                query_errors.append(name)
                publish_metric(name, -1)
            else:
                count = len(rows)
                print(f"  {name}: {count} finding(s)")
                publish_metric(name, count)
                if count > 0:
                    all_findings[name] = count
                    total += count
        except Exception as e:
            print(f"  ERROR in {name}: {e}")
            query_errors.append(name)
            publish_metric(name, -1)

    try:
        now = datetime.datetime.utcnow()
        metrics = cw.get_metric_statistics(
            Namespace='AWS/Athena',
            MetricName='EngineExecutionTime',
            Dimensions=[
                {'Name': 'WorkGroup', 'Value': WORKGROUP},
                {'Name': 'QueryState', 'Value': 'SUCCEEDED'},
            ],
            StartTime=now - datetime.timedelta(hours=24),
            EndTime=now,
            Period=86400,
            Statistics=['Maximum'],
        )
        datapoints = metrics.get('Datapoints', [])
        if datapoints:
            max_ms = max(dp['Maximum'] for dp in datapoints)
            max_sec = max_ms / 1000.0
            publish_metric('AthenaMaxQuerySeconds', max_sec)
            if max_sec > 60:
                print(f"  AthenaQueryPerformance: slowest query {max_sec:.1f}s")
                all_findings['AthenaQueryPerformance'] = 1
                total += 1
            else:
                print(f"  AthenaQueryPerformance: OK (max {max_sec:.1f}s)")
        else:
            print("  AthenaQueryPerformance: no queries in last 24h")
    except Exception as e:
        print(f"  AthenaQueryPerformance check error: {e}")

    publish_metric('TotalFindings', total)

    if all_findings or query_errors:
        summary_lines = [
            f"SIEM Detection Run — {total} finding(s) require attention",
            f"Lookback window: {lookback} minutes",
            "",
            "Detection results:",
        ]
        for det_name, count in all_findings.items():
            label = SIMULATION_SCENARIOS.get(det_name, '')
            tag = f" [{label}]" if label else ''
            summary_lines.append(f"  {det_name}: {count} finding(s){tag}")
        if query_errors:
            summary_lines += ["", "Query failures (check Lambda logs):"]
            for det_name in query_errors:
                summary_lines.append(f"  {det_name}")
        summary_lines += [
            "",
            f"Review results in Athena workgroup: org-siem",
            f"Region: {REGION}",
        ]
        sns.publish(
            TopicArn=SNS_ARN,
            Subject=f"[SIEM ALERT] {total} security finding(s) detected",
            Message="\n".join(summary_lines),
        )
        print(f"Alert published: {total} total findings")
    else:
        print("No findings -- all detections returned clean.")

    return {'findings': all_findings, 'total': total, 'errors': query_errors}
    PYTHON
  }
}

resource "aws_lambda_function" "siem_detector" {
  function_name    = "siem-detector"
  role             = aws_iam_role.siem_lambda.arn
  handler          = "detector.handler"
  runtime          = "python3.13"
  filename         = data.archive_file.siem_detector.output_path
  source_code_hash = data.archive_file.siem_detector.output_base64sha256
  timeout          = 300 # 5 minutes - Athena queries can be slow on first run
  memory_size      = 256
  kms_key_arn      = aws_kms_key.org_logs_cmk.arn

  environment {
    variables = {
      ATHENA_WORKGROUP = aws_athena_workgroup.siem.name
      GLUE_DATABASE    = aws_glue_catalog_database.siem.name
      RESULTS_LOCATION = "s3://${aws_s3_bucket.org_logs.id}/athena-results/"
      SNS_TOPIC_ARN    = aws_sns_topic.siem_alerts.arn
    }
  }

  tags = merge(local.common_tags, {
    Name = "siem-detector"
  })
}

# -- EventBridge Schedule ---------------------------------------------
# Disabled by default. Set var.siem_schedule_enabled = true to activate
# 15-minute polling. When disabled, invoke manually from the Lambda
# console or with: aws lambda invoke --function-name siem-detector ...

resource "aws_cloudwatch_event_rule" "siem_schedule" {
  name        = "siem-detector-schedule"
  description = "Runs the SIEM detection Lambda every 15 minutes"
  # Run once per hour. 15-minute intervals were tested and caused ~$19 in
  # Athena costs in 2 hours due to full-table scans on every invocation.
  # Hourly combined with the 70-minute lookback window in LOOKBACK_MINUTES
  # gives complete coverage with a 10-minute overlap buffer between runs.
  # To adjust frequency also update LOOKBACK_MINUTES in the Lambda code.
  schedule_expression = "rate(1 hour)"
  state               = var.siem_schedule_enabled ? "ENABLED" : "DISABLED"

  tags = merge(local.common_tags, {
    Name = "siem-detector-schedule"
  })
}

resource "aws_cloudwatch_event_target" "siem_schedule" {
  rule      = aws_cloudwatch_event_rule.siem_schedule.name
  target_id = "siem-detector-lambda"
  arn       = aws_lambda_function.siem_detector.arn
}

resource "aws_lambda_permission" "eventbridge_invoke" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.siem_detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.siem_schedule.arn
}

# -- CloudWatch Alarms ------------------------------------------------
# Alert when any detection metric is non-zero. These alarm on the custom
# metrics the Lambda writes to SIEM/Detections namespace.

locals {
  detection_names = [
    "ConsoleLoginWithoutMFA",
    "RootAccountActivity",
    "IAMPrivilegeEscalation",
    "UnauthorizedLogBucketAccess",
    "UnencryptedResourceCreation",
    "SecurityServiceTampering",
    "GuardDutyHighSeverity",
    "RejectedSensitivePorts",
    "CredentialExposure",
    "AthenaMaxQuerySeconds",
  ]
}

resource "aws_cloudwatch_metric_alarm" "siem_detection" {
  for_each = toset(local.detection_names)

  alarm_name          = "siem-${lower(replace(each.key, "/([A-Z])/", "-$1"))}"
  alarm_description   = "SIEM detection ${each.key} has findings - review Athena results"
  namespace           = "SIEM/Detections"
  metric_name         = each.key
  period              = 900
  evaluation_periods  = 1
  threshold           = 1
  statistic           = "Sum"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"

  alarm_actions = [aws_sns_topic.siem_alerts.arn]
  ok_actions    = [aws_sns_topic.siem_alerts.arn]

  tags = merge(local.common_tags, {
    Name = "siem-${each.key}"
  })
}
