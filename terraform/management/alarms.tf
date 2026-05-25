# terraform/management/alarms.tf

locals {
  alarm_defaults = {
    period              = 300
    evaluation_periods  = 1
    threshold           = 1
    statistic           = "Sum"
    comparison_operator = "GreaterThanOrEqualToThreshold"
    treat_missing_data  = "notBreaching"
  }
}

# -------------------------------------------------------
# 1. Root Account Usage  (CIS 3.3)
# -------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = "root-account-usage"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{$.userIdentity.type=\"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !=\"AwsServiceEvent\"}"

  metric_transformation {
    name          = "RootAccountUsage"
    namespace     = "SecurityMetrics/CloudTrail"
    value         = "1"
    default_value = "0"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = "root-account-usage"
  alarm_description   = "Root account activity detected — investigate immediately"
  metric_name         = aws_cloudwatch_log_metric_filter.root_usage.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.root_usage.metric_transformation[0].namespace
  period              = local.alarm_defaults.period
  evaluation_periods  = local.alarm_defaults.evaluation_periods
  threshold           = local.alarm_defaults.threshold
  statistic           = local.alarm_defaults.statistic
  comparison_operator = local.alarm_defaults.comparison_operator
  treat_missing_data  = local.alarm_defaults.treat_missing_data
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
  ok_actions          = [aws_sns_topic.security_alarms.arn]

  tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

# -------------------------------------------------------
# 2. Console Sign-In Without MFA  (CIS 3.2)
# -------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "console_no_mfa" {
  name           = "console-signin-without-mfa"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{$.eventName=\"ConsoleLogin\" && $.additionalEventData.MFAUsed !=\"Yes\" && $.userIdentity.type !=\"AssumedRole\" && $.responseElements.ConsoleLogin=\"Success\"}"

  metric_transformation {
    name          = "ConsoleSignInWithoutMFA"
    namespace     = "SecurityMetrics/CloudTrail"
    value         = "1"
    default_value = "0"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_metric_alarm" "console_no_mfa" {
  alarm_name          = "console-signin-without-mfa"
  alarm_description   = "Successful console sign-in occurred without MFA"
  metric_name         = aws_cloudwatch_log_metric_filter.console_no_mfa.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.console_no_mfa.metric_transformation[0].namespace
  period              = local.alarm_defaults.period
  evaluation_periods  = local.alarm_defaults.evaluation_periods
  threshold           = local.alarm_defaults.threshold
  statistic           = local.alarm_defaults.statistic
  comparison_operator = local.alarm_defaults.comparison_operator
  treat_missing_data  = local.alarm_defaults.treat_missing_data
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
  ok_actions          = [aws_sns_topic.security_alarms.arn]

  tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

# -------------------------------------------------------
# 3. Unauthorized API Calls  (CIS 3.1)
# -------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "unauthorized_api" {
  name           = "unauthorized-api-calls"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{($.errorCode=\"*UnauthorizedAccess*\") || ($.errorCode=\"AccessDenied*\")}"

  metric_transformation {
    name          = "UnauthorizedAPICalls"
    namespace     = "SecurityMetrics/CloudTrail"
    value         = "1"
    default_value = "0"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api" {
  alarm_name          = "unauthorized-api-calls"
  alarm_description   = "One or more unauthorized API calls detected"
  metric_name         = aws_cloudwatch_log_metric_filter.unauthorized_api.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.unauthorized_api.metric_transformation[0].namespace
  period              = local.alarm_defaults.period
  evaluation_periods  = local.alarm_defaults.evaluation_periods
  threshold           = local.alarm_defaults.threshold
  statistic           = local.alarm_defaults.statistic
  comparison_operator = local.alarm_defaults.comparison_operator
  treat_missing_data  = local.alarm_defaults.treat_missing_data
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
  ok_actions          = [aws_sns_topic.security_alarms.arn]

  tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

# -------------------------------------------------------
# 4. SCP Changes  (CIS 3.14)
# -------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "scp_changes" {
  name           = "scp-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{$.eventSource=\"organizations.amazonaws.com\" && ($.eventName=\"CreatePolicy\" || $.eventName=\"DeletePolicy\" || $.eventName=\"UpdatePolicy\" || $.eventName=\"AttachPolicy\" || $.eventName=\"DetachPolicy\" || $.eventName=\"EnablePolicyType\" || $.eventName=\"DisablePolicyType\")}"

  metric_transformation {
    name          = "SCPChanges"
    namespace     = "SecurityMetrics/CloudTrail"
    value         = "1"
    default_value = "0"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_metric_alarm" "scp_changes" {
  alarm_name          = "scp-changes"
  alarm_description   = "An AWS Organizations SCP was created, modified, attached, or detached"
  metric_name         = aws_cloudwatch_log_metric_filter.scp_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.scp_changes.metric_transformation[0].namespace
  period              = local.alarm_defaults.period
  evaluation_periods  = local.alarm_defaults.evaluation_periods
  threshold           = local.alarm_defaults.threshold
  statistic           = local.alarm_defaults.statistic
  comparison_operator = local.alarm_defaults.comparison_operator
  treat_missing_data  = local.alarm_defaults.treat_missing_data
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
  ok_actions          = [aws_sns_topic.security_alarms.arn]

  tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}

# -------------------------------------------------------
# 5. CloudTrail Changes
# -------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "cloudtrail_changes" {
  name           = "cloudtrail-changes"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{($.eventName=\"CreateTrail\") || ($.eventName=\"UpdateTrail\") || ($.eventName=\"DeleteTrail\") || ($.eventName=\"StartLogging\") || ($.eventName=\"StopLogging\")}"

  metric_transformation {
    name          = "CloudTrailChanges"
    namespace     = "SecurityMetrics/CloudTrail"
    value         = "1"
    default_value = "0"
  }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_cloudwatch_metric_alarm" "cloudtrail_changes" {
  alarm_name          = "cloudtrail-changes"
  alarm_description   = "The organization CloudTrail trail was created, modified, or stopped"
  metric_name         = aws_cloudwatch_log_metric_filter.cloudtrail_changes.metric_transformation[0].name
  namespace           = aws_cloudwatch_log_metric_filter.cloudtrail_changes.metric_transformation[0].namespace
  period              = local.alarm_defaults.period
  evaluation_periods  = local.alarm_defaults.evaluation_periods
  threshold           = local.alarm_defaults.threshold
  statistic           = local.alarm_defaults.statistic
  comparison_operator = local.alarm_defaults.comparison_operator
  treat_missing_data  = local.alarm_defaults.treat_missing_data
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
  ok_actions          = [aws_sns_topic.security_alarms.arn]

  tags = local.common_tags

  lifecycle {
    prevent_destroy = true
  }
}