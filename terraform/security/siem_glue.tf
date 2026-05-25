# terraform/security/siem_glue.tf
# =====================================================================
# AWS Glue Data Catalog - org-siem database and table definitions
#
# Glue Crawlers are not available in us-west-1 so table schemas are
# defined directly via aws_glue_catalog_table resources. The Glue Data
# Catalog API accepts table definitions in all regions that support the
# Data Catalog, including us-west-1. Athena reads these definitions
# exactly as it would tables created by a crawler or CREATE TABLE DDL.
#
# Tables defined:
#   cloudtrail                       - CloudTrail JSON logs (all org accounts)
#   guardduty                        - GuardDuty findings exported to S3
#   vpc_flow_logs                    - VPC Flow Logs across all spokes
#                                      (Parquet + partition projection)
#   network_firewall_external_flow   - Network Firewall flow logs (north-south)
#   network_firewall_external_alert  - Network Firewall alert logs (north-south)
#   network_firewall_internal_flow   - Network Firewall flow logs (east-west)
#   network_firewall_internal_alert  - Network Firewall alert logs (east-west)
#   dns_query_logs                   - Route 53 Resolver query logs
# =====================================================================

resource "aws_glue_catalog_database" "siem" {
  name        = "org-siem"
  description = "Security data lake - org-wide logs from CloudTrail, GuardDuty, Network Firewall, VPC Flow Logs"

  tags = merge(local.common_tags, {
    Name = "org-siem"
  })

  depends_on = [aws_lakeformation_data_lake_settings.main]
}

# -- IAM Role (used by Athena to access the catalog) ------------------

resource "aws_iam_role" "glue_crawler" {
  name = "siem-glue-catalog-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "glue.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })

  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "glue_service" {
  role       = aws_iam_role.glue_crawler.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
}

resource "aws_iam_role_policy" "glue_s3_kms" {
  name = "siem-glue-s3-kms"
  role = aws_iam_role.glue_crawler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Read"
        Effect = "Allow"
        Action = ["s3:GetObject", "s3:ListBucket"]
        Resource = [
          aws_s3_bucket.org_logs.arn,
          "${aws_s3_bucket.org_logs.arn}/*",
        ]
      },
      {
        Sid      = "KMSDecrypt"
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:DescribeKey", "kms:GenerateDataKey"]
        Resource = [aws_kms_key.org_logs_cmk.arn]
      },
    ]
  })
}

# -- Table: CloudTrail ------------------------------------------------
# Uses the built-in CloudTrail SerDe so Athena can read compressed
# JSON CloudTrail records natively.

resource "aws_glue_catalog_table" "cloudtrail" {
  name          = "cloudtrail"
  database_name = aws_glue_catalog_database.siem.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "cloudtrail"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/cloudtrail/AWSLogs/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "apiversion"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "serviceeventdetails"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
  }
}

# -- Table: GuardDuty Findings ----------------------------------------

resource "aws_glue_catalog_table" "guardduty" {
  name          = "guardduty"
  database_name = aws_glue_catalog_database.siem.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "json"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/guardduty/AWSLogs/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "schemaversion"
      type = "string"
    }
    columns {
      name = "accountid"
      type = "string"
    }
    columns {
      name = "region"
      type = "string"
    }
    columns {
      name = "id"
      type = "string"
    }
    columns {
      name = "arn"
      type = "string"
    }
    columns {
      name = "type"
      type = "string"
    }
    columns {
      name = "resource"
      type = "string"
    }
    columns {
      name = "service"
      type = "string"
    }
    columns {
      name = "severity"
      type = "double"
    }
    columns {
      name = "createdat"
      type = "string"
    }
    columns {
      name = "updatedat"
      type = "string"
    }
    columns {
      name = "title"
      type = "string"
    }
    columns {
      name = "description"
      type = "string"
    }
  }
}

# -- Table: VPC Flow Logs ---------------------------------------------
# Space-delimited format matching the custom log_format in siem_flowlogs.tf.
# Partitioned by account, region, and date for efficient querying.

# VPC Flow Logs across every VPC in the org are delivered to this single
# S3 bucket under sub-prefixes per spoke (networking/, security/,
# corporate/, web/). Each sub-prefix follows the hive-compatible layout:
#   <spoke>/AWSLogs/aws-account-id=<acct>/aws-service=vpcflowlogs/
#   aws-region=<region>/year=YYYY/month=MM/day=DD/hour=HH/<files>.parquet
#
# Logs are Parquet (file_format="parquet" + hive_compatible_partitions=true
# in the aws_flow_log resources). Athena reads them via this single table
# with partition projection so no manual ALTER TABLE ADD PARTITION is
# required and queries run against the latest data automatically.
resource "aws_glue_catalog_table" "vpc_flow_logs" {
  name          = "vpc_flow_logs"
  database_name = aws_glue_catalog_database.siem.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "EXTERNAL"           = "TRUE"
    "classification"     = "parquet"
    "has_encrypted_data" = "true"

    # -- Partition projection --
    "projection.enabled" = "true"

    "projection.spoke.type"   = "enum"
    "projection.spoke.values" = "networking,security,corporate,web"

    # enum (vs injected) so queries don't need a static aws_account_id
    # equality filter. Values come from the four resolved account IDs the
    # security workspace receives as variables. Empty strings filtered out
    # so the pipeline's first-ever apply (before all IDs are resolved)
    # doesn't fail; subsequent applies pick up all four.
    "projection.aws_account_id.type" = "enum"
    "projection.aws_account_id.values" = join(",", compact([
      var.account_id,           # security account (this workspace's own)
      var.networking_account_id,
      var.corporate_account_id,
      var.web_account_id,
    ]))

    "projection.aws_service.type"   = "enum"
    "projection.aws_service.values" = "vpcflowlogs"

    "projection.aws_region.type"   = "enum"
    "projection.aws_region.values" = data.aws_region.current.name

    "projection.year.type"  = "integer"
    "projection.year.range" = "2025,2030"

    "projection.month.type"   = "integer"
    "projection.month.range"  = "1,12"
    "projection.month.digits" = "2"

    "projection.day.type"   = "integer"
    "projection.day.range"  = "1,31"
    "projection.day.digits" = "2"

    "projection.hour.type"   = "integer"
    "projection.hour.range"  = "0,23"
    "projection.hour.digits" = "2"

    "storage.location.template" = "s3://${aws_s3_bucket.org_logs.id}/vpc-flow-logs/$${spoke}/AWSLogs/aws-account-id=$${aws_account_id}/aws-service=$${aws_service}/aws-region=$${aws_region}/year=$${year}/month=$${month}/day=$${day}/hour=$${hour}/"
  }

  partition_keys {
    name = "spoke"
    type = "string"
  }
  partition_keys {
    name = "aws_account_id"
    type = "string"
  }
  partition_keys {
    name = "aws_service"
    type = "string"
  }
  partition_keys {
    name = "aws_region"
    type = "string"
  }
  partition_keys {
    name = "year"
    type = "string"
  }
  partition_keys {
    name = "month"
    type = "string"
  }
  partition_keys {
    name = "day"
    type = "string"
  }
  partition_keys {
    name = "hour"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/vpc-flow-logs/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
      parameters = {
        "serialization.format" = "1"
      }
    }

    # VPC Flow Logs default v9 fields (matches the log_format string in
    # networking_flowlogs_s3gw.tf and siem_flowlogs.tf).
    columns {
      name = "version"
      type = "int"
    }
    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "interface_id"
      type = "string"
    }
    columns {
      name = "srcaddr"
      type = "string"
    }
    columns {
      name = "dstaddr"
      type = "string"
    }
    columns {
      name = "srcport"
      type = "int"
    }
    columns {
      name = "dstport"
      type = "int"
    }
    columns {
      name = "protocol"
      type = "bigint"
    }
    columns {
      name = "packets"
      type = "bigint"
    }
    columns {
      name = "bytes"
      type = "bigint"
    }
    columns {
      name = "start"
      type = "bigint"
    }
    columns {
      name = "end"
      type = "bigint"
    }
    columns {
      name = "action"
      type = "string"
    }
    columns {
      name = "log_status"
      type = "string"
    }
    columns {
      name = "vpc_id"
      type = "string"
    }
    columns {
      name = "subnet_id"
      type = "string"
    }
    columns {
      name = "instance_id"
      type = "string"
    }
    columns {
      name = "tcp_flags"
      type = "int"
    }
    columns {
      name = "type"
      type = "string"
    }
    columns {
      name = "pkt_srcaddr"
      type = "string"
    }
    columns {
      name = "pkt_dstaddr"
      type = "string"
    }
  }
}

# -- Table: Network Firewall Flow Logs --------------------------------

# Network Firewall flow + alert logs are split by traffic class per the
# external/internal firewall design (see terraform/networking/network_firewall.tf):
#   network-firewall/external/flow/    -- north-south web (external NF)
#   network-firewall/external/alert/
#   network-firewall/internal/flow/    -- east-west + spoke egress (internal NF)
#   network-firewall/internal/alert/
# One Glue table per (class, log_type) pair so queries scope cleanly.

resource "aws_glue_catalog_table" "network_firewall_external_flow" {
  name          = "network_firewall_external_flow"
  database_name = aws_glue_catalog_database.siem.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "json"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/network-firewall/external/flow/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "firewall_name"
      type = "string"
    }
    columns {
      name = "availability_zone"
      type = "string"
    }
    columns {
      name = "event_timestamp"
      type = "string"
    }
    columns {
      name = "event"
      type = "struct<timestamp:string,flow_id:bigint,event_type:string,src_ip:string,src_port:int,dest_ip:string,dest_port:int,proto:string,app_proto:string,bytes:bigint,packets:bigint>"
    }
  }
}

resource "aws_glue_catalog_table" "network_firewall_internal_flow" {
  name          = "network_firewall_internal_flow"
  database_name = aws_glue_catalog_database.siem.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "json"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/network-firewall/internal/flow/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "firewall_name"
      type = "string"
    }
    columns {
      name = "availability_zone"
      type = "string"
    }
    columns {
      name = "event_timestamp"
      type = "string"
    }
    columns {
      name = "event"
      type = "struct<timestamp:string,flow_id:bigint,event_type:string,src_ip:string,src_port:int,dest_ip:string,dest_port:int,proto:string,app_proto:string,bytes:bigint,packets:bigint>"
    }
  }
}

# -- Table: Network Firewall Alert Logs (external + internal) ---------

resource "aws_glue_catalog_table" "network_firewall_external_alert" {
  name          = "network_firewall_external_alert"
  database_name = aws_glue_catalog_database.siem.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "json"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/network-firewall/external/alert/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "firewall_name"
      type = "string"
    }
    columns {
      name = "availability_zone"
      type = "string"
    }
    columns {
      name = "event_timestamp"
      type = "string"
    }
    columns {
      name = "event"
      type = "struct<timestamp:string,flow_id:bigint,event_type:string,src_ip:string,src_port:int,dest_ip:string,dest_port:int,proto:string,alert:struct<action:string,gid:int,signature_id:bigint,rev:int,signature:string,category:string,severity:int>>"
    }
  }
}

resource "aws_glue_catalog_table" "network_firewall_internal_alert" {
  name          = "network_firewall_internal_alert"
  database_name = aws_glue_catalog_database.siem.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "json"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/network-firewall/internal/alert/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "firewall_name"
      type = "string"
    }
    columns {
      name = "availability_zone"
      type = "string"
    }
    columns {
      name = "event_timestamp"
      type = "string"
    }
    columns {
      name = "event"
      type = "struct<timestamp:string,flow_id:bigint,event_type:string,src_ip:string,src_port:int,dest_ip:string,dest_port:int,proto:string,alert:struct<action:string,gid:int,signature_id:bigint,rev:int,signature:string,category:string,severity:int>>"
    }
  }
}

# -- Table: Route 53 DNS Query Logs -----------------------------------

resource "aws_glue_catalog_table" "dns_query_logs" {
  name          = "dns_query_logs"
  database_name = aws_glue_catalog_database.siem.name

  table_type = "EXTERNAL_TABLE"

  parameters = {
    "classification"     = "json"
    "has_encrypted_data" = "true"
    "EXTERNAL"           = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.org_logs.id}/route53-query-logs/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters            = { "serialization.format" = "1" }
    }

    columns {
      name = "version"
      type = "string"
    }
    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "region"
      type = "string"
    }
    columns {
      name = "vpc_id"
      type = "string"
    }
    columns {
      name = "query_timestamp"
      type = "string"
    }
    columns {
      name = "query_name"
      type = "string"
    }
    columns {
      name = "query_type"
      type = "string"
    }
    columns {
      name = "query_class"
      type = "string"
    }
    columns {
      name = "rcode"
      type = "string"
    }
    columns {
      name = "answers"
      type = "array<struct<rdata:string,type:string,class:string>>"
    }
    columns {
      name = "srcaddr"
      type = "string"
    }
    columns {
      name = "srcport"
      type = "int"
    }
    columns {
      name = "transport"
      type = "string"
    }
    columns {
      name = "srcids"
      type = "struct<instance:string,resolver_endpoint:string>"
    }
  }
}

# =====================================================================
# Lake Formation — IAM passthrough mode
# =====================================================================
# Without this, Lake Formation defaults to empty CreateDatabase/Table
# permissions, which locks out every IAM principal (including admin
# roles) from seeing Glue databases until explicit LF grants are added.
# Setting IAM_ALLOWED_PRINCIPALS: ALL restores the standard behavior
# where IAM policies control Glue catalog access.
#
# Must be applied before the Glue catalog database is created so the
# database inherits the correct default permissions automatically.

resource "aws_lakeformation_data_lake_settings" "main" {
  create_database_default_permissions {
    permissions = ["ALL"]
    principal   = "IAM_ALLOWED_PRINCIPALS"
  }

  create_table_default_permissions {
    permissions = ["ALL"]
    principal   = "IAM_ALLOWED_PRINCIPALS"
  }
}
