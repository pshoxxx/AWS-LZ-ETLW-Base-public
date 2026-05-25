# terraform/web/aurora.tf
# =====================================================================
# Aurora Serverless v2 (MySQL 8.0 compatible)
# Scales to 0.5 ACU minimum; no instance management required.
# =====================================================================

resource "aws_db_subnet_group" "aurora" {
  name        = "web-aurora-subnet-group"
  description = "Private subnets for Aurora Serverless v2"
  subnet_ids  = aws_subnet.private[*].id

  tags = merge(local.common_tags, {
    Name = "web-aurora-subnet-group"
  })
}

resource "aws_rds_cluster" "main" {
  cluster_identifier          = "web-aurora"
  engine                      = "aurora-mysql"
  engine_version              = "8.0.mysql_aurora.3.04.0"
  engine_mode                 = "provisioned"
  database_name               = "webdb"
  master_username             = "admin"
  manage_master_user_password = true

  db_subnet_group_name   = aws_db_subnet_group.aurora.name
  vpc_security_group_ids = [aws_security_group.aurora.id]

  storage_encrypted                   = true
  iam_database_authentication_enabled = true
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["audit", "error", "general", "slowquery"]

  skip_final_snapshot = true
  deletion_protection = false

  serverlessv2_scaling_configuration {
    min_capacity = var.aurora_min_capacity
    max_capacity = var.aurora_max_capacity
  }

  tags = merge(local.common_tags, {
    Name = "web-aurora"
  })
}

resource "aws_rds_cluster_instance" "main" {
  identifier         = "web-aurora-instance-1"
  cluster_identifier = aws_rds_cluster.main.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.main.engine
  engine_version     = aws_rds_cluster.main.engine_version

  db_subnet_group_name       = aws_db_subnet_group.aurora.name
  auto_minor_version_upgrade = true

  tags = merge(local.common_tags, {
    Name = "web-aurora-instance-1"
  })
}
