# =================================================================================
# The Bridge - Identity Stack
# =================================================================================
# Este arquivo cria a "Ponte" de autenticação entre GitHub Actions e AWS.
# Ele define o OIDC Provider, a Role e as Políticas de Permissão.
# =================================================================================

variable "security_email" {
  description = "Email para receber alertas de segurança críticos (CloudWatch/SNS)"
  type        = string
}

# Data source para obter Account ID (necessário para Key Policy)
data "aws_caller_identity" "current" {}

# Data source para obter a Região atual (necessário para Key Policy de Logs)
data "aws_region" "current" {}

# --- 1. OIDC Provider ---
# Permite que a AWS confie nos tokens do GitHub Actions
data "tls_certificate" "github" {
  url = "https://token.actions.githubusercontent.com/.well-known/openid-configuration"
}

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.github.certificates[0].sha1_fingerprint]

  lifecycle {
    # prevent_destroy = true # Commented out for Bootstrap/Rename phase
    ignore_changes  = [thumbprint_list]
  }
}

# --- 2. IAM Role ---
# A Role que o GitHub Actions irá assumir
data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = [for repo in var.github_repos : "repo:${repo}:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = lower("${var.project_name}-github-actions-role")
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json
  description        = "Role de Bootstrap criada pela ferramenta The Bridge"

  lifecycle {
    # prevent_destroy = true # Commented out for Bootstrap/Rename phase
  }
}

# --- 3. Permissions Boundary (A Blindagem) ---
# Esta política define o TETO MÁXIMO de permissões que qualquer Role criada pelo pipeline pode ter.
# Mesmo que o Terraform tente dar "AdministratorAccess", esta boundary bloqueará ações críticas de IAM.
resource "aws_iam_policy" "boundary" {
  name        = lower("${var.project_name}-infra-boundary")
  description = "Boundary que impede escalacao de privilegio em roles criadas pelo CI/CD"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Permite tudo de infraestrutura (EC2, S3, RDS, etc)
      {
        Sid      = "AllowInfrastructure"
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      },
      # 1. BLOQUEIO GERAL: Impede criação de portas dos fundos (IAM Users/Login)
      {
        Sid      = "DenyIAMUserManagement"
        Effect   = "Deny"
        Action   = [
          "iam:CreateUser", "iam:DeleteUser", "iam:UpdateUser", "iam:CreateLoginProfile",
          "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateGroup"
        ]
        Resource = "*"
      },
      # 2. SELF-PROTECTION: Impede que a Role altere suas próprias regras de segurança
      {
        Sid      = "DenyCriticalConfigTampering"
        Effect   = "Deny"
        Action   = [
          "iam:DeletePolicy", "iam:DeletePolicyVersion",
          "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
          "iam:DeleteRole", "iam:UpdateAssumeRolePolicy"
        ]
        Resource = [
          "arn:aws:iam::*:policy/*-infra-boundary",
          "arn:aws:iam::*:role/*-github-actions-role"
        ]
      }
    ]
  })
}

# --- 4. IAM Policy (Permissões do Pipeline) ---
# Define o que o GitHub Actions pode fazer.
# Dividida em duas partes para evitar o limite de 6144 caracteres da AWS.
resource "aws_iam_policy" "devops_policy_base" {
  name        = lower("${var.project_name}-devops-policy-base")
  description = "Permissoes Base (S3, DynamoDB, EC2) para o CI/CD"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # S3 e DynamoDB (Backend Terraform)
      {
        Sid    = "TerraformBackendAccess"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket", "s3:ListBucket", "s3:Get*", "s3:Put*", "s3:DeleteObject",
          "s3:GetBucketVersioning", "s3:PutBucketVersioning", "s3:GetBucketEncryption", "s3:PutBucketEncryption",
          "dynamodb:CreateTable", "dynamodb:DeleteTable", "dynamodb:UpdateTable",
          "dynamodb:TagResource", "dynamodb:UntagResource", "dynamodb:ListTagsOfResource",
          "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:Scan",
          "dynamodb:DescribeTable", "dynamodb:DescribeContinuousBackups", "dynamodb:UpdateContinuousBackups", "dynamodb:DescribeTimeToLive", "dynamodb:UpdateTimeToLive"
        ]
        Resource = [
          "arn:aws:s3:::${lower(var.project_name)}-tfstate-bucket",
          "arn:aws:s3:::${lower(var.project_name)}-tfstate-bucket/*",
          "arn:aws:dynamodb:*:*:table/${lower(var.project_name)}-tf-lock-table",
          "arn:aws:s3:::${lower(var.project_name)}-config-logs",
          "arn:aws:s3:::${lower(var.project_name)}-config-logs/*",
          "arn:aws:s3:::${lower(var.project_name)}-audit-logs",
          "arn:aws:s3:::${lower(var.project_name)}-audit-logs/*"
        ]
      },
      # Permissões Gerais de Leitura (Para Importação/Discovery)
      {
        Sid    = "GeneralRead"
        Effect = "Allow"
        Action = [
          "s3:ListAllMyBuckets",
          "s3:GetBucketLocation",
          "ec2:Describe*",
          "ecr:Describe*",
          "iam:List*",
          "iam:Get*"
        ]
        Resource = "*"
      },
      # Gerenciamento de EC2 e Rede (VULN-004: Least Privilege)
      {
        Sid    = "EC2ReadAndSetup"
        Effect = "Allow"
        Action = [
          "ec2:Describe*",
          "ec2:CreateSecurityGroup", # Criação é permitida globalmente (pois não tem tag ainda), mas modificação será restrita
          "ec2:CreateTags", "ec2:RunInstances", # RunInstances é complexo restringir por tag na criação, controlado via AMI/Subnet se necessário
          "ec2:AllocateAddress", "ec2:AssociateAddress", "ec2:ReleaseAddress"
        ]
        Resource = "*"
      },
      {
        Sid    = "EC2NetworkModificationScoped"
        Effect = "Allow"
        Action = [
          "ec2:DeleteSecurityGroup",
          "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
          "ec2:AuthorizeSecurityGroupEgress", "ec2:RevokeSecurityGroupEgress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress", "ec2:UpdateSecurityGroupRuleDescriptionsEgress"
        ]
        # SEGURANÇA: Impede que o pipeline abra portas em Security Groups de outros projetos (ex: DB Prod, VPN)
        Resource = "arn:aws:ec2:*:*:security-group/*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = var.project_name
          }
        }
      },
      {
        Sid    = "EC2DestructiveActionsScoped"
        Effect = "Allow"
        Action = [
          "ec2:TerminateInstances",
          "ec2:StopInstances",
          "ec2:RebootInstances",
          "ec2:AttachVolume",
          "ec2:DetachVolume"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = var.project_name
          }
        }
      },
      # 7. DENY: Proteção contra exposição pública acidental do State (Data Leak Prevention)
      {
        Sid    = "DenyPublicStateBucket"
        Effect = "Deny"
        Action = "s3:PutBucketAcl"
        Resource = [
          "arn:aws:s3:::${lower(var.project_name)}-tfstate-bucket",
          "arn:aws:s3:::${lower(var.project_name)}-tfstate-bucket/*"
        ]
        Condition = {
          StringLike = {
            "s3:x-amz-acl" = ["public-read", "public-read-write"]
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy" "devops_policy_services" {
  name        = lower("${var.project_name}-devops-policy-services")
  description = "Permissoes de Servicos (IAM, ECR, SSM, Logs, KMS) para o CI/CD"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # Gerenciamento de IAM - CRIAÇÃO DE ROLES (Com Restrição de Boundary)
      {
        Sid    = "IAMCreateRoleWithBoundary"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:PutRolePermissionsBoundary"
        ]
        Resource = "arn:aws:iam::*:role/*"
        # AQUI ESTÁ A SEGURANÇA: Só permite criar role SE anexar a boundary
        Condition = {
          StringEquals = {
            "iam:PermissionsBoundary" = aws_iam_policy.boundary.arn
          }
        }
      },
      {
        Sid    = "IAMReadGlobal"
        Effect = "Allow"
        Action = [
          "iam:Get*", "iam:List*"
        ]
        Resource = "*"
      },
      {
        Sid    = "IAMWriteScoped"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:DeleteRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateRole", "iam:UpdateAssumeRolePolicy", "iam:UpdateRoleDescription",
          "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", "iam:AddRoleToInstanceProfile", 
          "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePolicy", "iam:DeleteRolePolicy",
          "iam:CreatePolicy", "iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion", "iam:TagPolicy", "iam:UntagPolicy",
          "iam:CreateOpenIDConnectProvider", "iam:DeleteOpenIDConnectProvider",
          "iam:GetOpenIDConnectProvider", "iam:TagOpenIDConnectProvider", "iam:UntagOpenIDConnectProvider"
        ]
        Resource = [
          # SEGURANÇA: Restringe alterações apenas a recursos que comecem com o nome do projeto.
          "arn:aws:iam::*:role/${lower(var.project_name)}-*",
          "arn:aws:iam::*:instance-profile/${lower(var.project_name)}-*",
          "arn:aws:iam::*:policy/${lower(var.project_name)}-*",
          "arn:aws:iam::*:oidc-provider/*"
        ]
      },
      # VULN-003: iam:PassRole Restrito
      {
        Sid    = "IAMPassRole"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = "arn:aws:iam::*:role/${lower(var.project_name)}-*"
      },
      # Gerenciamento de ECR
      {
        Sid    = "ECRManagement"
        Effect = "Allow"
        Action = [
          "ecr:CreateRepository", "ecr:DeleteRepository",
          "ecr:DescribeRepositories", "ecr:ListImages",
          "ecr:BatchCheckLayerAvailability", "ecr:GetDownloadUrlForLayer",
          "ecr:BatchGetImage", "ecr:PutImage", "ecr:InitiateLayerUpload",
          "ecr:UploadLayerPart", "ecr:CompleteLayerUpload",
          "ecr:SetRepositoryPolicy", "ecr:DeleteRepositoryPolicy",
          "ecr:GetRepositoryPolicy",
          "ecr:PutLifecyclePolicy", "ecr:DeleteLifecyclePolicy",
          "ecr:TagResource", "ecr:UntagResource", "ecr:ListTagsForResource"
        ]
        # SEGURANÇA: Restringe acesso apenas aos repositórios que começam com o nome do projeto
        Resource = "arn:aws:ecr:*:*:repository/${lower(var.project_name)}-*"
      },
      {
        Sid    = "ECRAuth"
        Effect = "Allow"
        Action = "ecr:GetAuthorizationToken"
        Resource = "*"
      },
      # 5. SSM (Parameter Store & Run Command)
      {
        Sid    = "SSMParameterStoreScoped"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter", "ssm:GetParameters", "ssm:PutParameter", "ssm:DeleteParameter", "ssm:GetParametersByPath",
          "ssm:AddTagsToResource", "ssm:ListTagsForResource", "ssm:RemoveTagsFromResource"
        ]
        # SEGURANÇA: Isola os parâmetros (segredos) por projeto.
        Resource = "arn:aws:ssm:*:*:parameter/${lower(var.project_name)}/*"
      },
      {
        Sid    = "SSMReadGlobal"
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstanceInformation", "ssm:GetCommandInvocation", "ssm:ListCommandInvocations", "ssm:DescribeParameters", "ssm:ListCommands"
        ]
        Resource = "*"
      },
      {
        Sid    = "SSMRunCommandScoped"
        Effect = "Allow"
        Action = "ssm:SendCommand"
        Resource = "*"
        # SEGURANÇA: Impede execução de comandos em instâncias de outros projetos
        Condition = {
          StringEquals = {
            "aws:ResourceTag/Project" = var.project_name
          }
        }
      },
      # 6. Observability & General
      {
        Sid    = "Observability"
        Effect = "Allow"
        Action = [
          "config:PutConfigurationRecorder", "config:PutDeliveryChannel", "config:StartConfigurationRecorder", "config:StopConfigurationRecorder",
          "config:PutConfigRule", "config:DeleteConfigRule", "config:PutRetentionConfiguration",
          "config:DeleteConfigurationRecorder", "config:DeleteDeliveryChannel",
          "config:DescribeConfigurationRecorders", "config:DescribeDeliveryChannels", "config:DescribeConfigurationRecorderStatus",
          "config:DescribeConfigRules",
          "config:TagResource", "config:UntagResource", "config:ListTagsForResource",
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogGroups",
          "logs:TagResource", "logs:ListTagsForResource", "logs:UntagResource", "logs:DeleteLogGroup", "logs:PutRetentionPolicy",
          "logs:AssociateKmsKey", "logs:PutMetricFilter", "logs:DeleteMetricFilter", "logs:DescribeMetricFilters",
          "cloudwatch:PutMetricData",
          "cloudwatch:PutMetricAlarm",
          "cloudwatch:DeleteAlarms",
          "cloudwatch:DescribeAlarms",
          "cloudwatch:TagResource",
          "cloudwatch:UntagResource",
          "cloudwatch:ListTagsForResource",
          "cloudtrail:CreateTrail",
          "cloudtrail:UpdateTrail",
          "cloudtrail:DeleteTrail",
          "cloudtrail:StartLogging",
          "cloudtrail:StopLogging",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails",
          "cloudtrail:GetTrail",
          "cloudtrail:PutEventSelectors",
          "cloudtrail:ListTags",
          "cloudtrail:AddTags",
          "cloudtrail:RemoveTags",
          "sts:GetCallerIdentity"
        ]
        Resource = "*"
      },
      # 7. KMS Encryption (Adicionado para suportar chaves gerenciadas)
      {
        Sid    = "KMSEncryption"
        Effect = "Allow"
        Action = [
          "kms:CreateKey", "kms:DescribeKey", "kms:EnableKey", "kms:DisableKey", "kms:UpdateKeyDescription",
          "kms:TagResource", "kms:UntagResource", "kms:ListResourceTags", "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion",
          "kms:PutKeyPolicy", "kms:GetKeyPolicy", "kms:GetKeyRotationStatus", "kms:EnableKeyRotation", "kms:DisableKeyRotation", "kms:CreateGrant",
          "kms:CreateAlias", "kms:DeleteAlias", "kms:UpdateAlias", "kms:ListAliases"
        ]
        Resource = "*"
      },
      # 8. SNS Topics (Adicionado para alertas de segurança)
      {
        Sid    = "SNSTopics"
        Effect = "Allow"
        Action = [
          "sns:CreateTopic", "sns:DeleteTopic", "sns:Subscribe", "sns:Unsubscribe",
          "sns:GetTopicAttributes", "sns:SetTopicAttributes", "sns:ListTagsForResource", "sns:TagResource", "sns:UntagResource",
          "sns:Publish", "sns:GetSubscriptionAttributes"
        ]
        Resource = "arn:aws:sns:*:*:*${lower(var.project_name)}*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "devops_base" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.devops_policy_base.arn
}

resource "aws_iam_role_policy_attachment" "devops_services" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.devops_policy_services.arn
}

# --- 5. CloudTrail (Auditoria) ---
# VULN-002: Habilitar CloudTrail com validação de integridade
resource "aws_s3_bucket" "audit_logs" {
  bucket        = lower("${var.project_name}-audit-logs")
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket                  = aws_s3_bucket.audit_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.audit_logs.arn
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.audit_logs.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "main" {
  name                          = lower("${var.project_name}-main-trail")
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudtrail_cloudwatch.arn
  kms_key_id                    = aws_kms_key.terraform_state.arn
  depends_on                    = [aws_s3_bucket_policy.audit_logs]
}

# --- 6. Terraform State Foundation (Bootstrap) ---
# Cria o Bucket e a Tabela de Lock para que os pipelines de IaC tenham onde guardar o estado.
# Isso fecha o ciclo: O Bootstrap cria a Identidade E o Armazenamento.

resource "aws_s3_bucket" "terraform_state" {
  bucket = lower("${var.project_name}-tfstate-bucket")

  lifecycle {
    # prevent_destroy = true # Commented out for Bootstrap/Rename phase
  }
}

resource "aws_s3_bucket_versioning" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  versioning_configuration {
    status = "Enabled"
  }
}

# --- 7. KMS Encryption (Customer Managed Key) ---
# VULN-001/Melhoria: Controle total sobre chaves de criptografia (Rotação/Auditoria)

resource "aws_kms_key" "terraform_state" {
  description             = "KMS key for Terraform state encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Purpose = "TerraformStateEncryption"
  }
}

resource "aws_kms_alias" "terraform_state" {
  name          = "alias/${lower(var.project_name)}-tfstate-key"
  target_key_id = aws_kms_key.terraform_state.key_id
}

resource "aws_kms_key_policy" "terraform_state" {
  key_id = aws_kms_key.terraform_state.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "Allow GitHub Actions Role"
        Effect = "Allow"
        Principal = { AWS = aws_iam_role.github_actions.arn }
        Action = [
          "kms:Decrypt", "kms:DescribeKey", "kms:Encrypt", "kms:GenerateDataKey"
        ]
        Resource = "*"
      },
      {
        Sid    = "Allow AWS Services"
        Effect = "Allow"
        Principal = {
          Service = ["cloudtrail.amazonaws.com", "config.amazonaws.com", "logs.${data.aws_region.current.name}.amazonaws.com", "sns.amazonaws.com"]
        }
        Action = [
          "kms:Encrypt", "kms:Decrypt", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:DescribeKey"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_s3_bucket_server_side_encryption_configuration" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "terraform_state" {
  bucket = aws_s3_bucket.terraform_state.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_dynamodb_table" "terraform_lock" {
  name         = lower("${var.project_name}-tf-lock-table")
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"

  attribute {
    name = "LockID"
    type = "S"
  }

  lifecycle {
    # prevent_destroy = true # Commented out for Bootstrap/Rename phase
  }
}

output "permissions_boundary_arn" {
  description = "ARN da Policy de Permissions Boundary (Use na variável 'PERMISSIONS_BOUNDARY_ARN' do GitHub)."
  value       = aws_iam_policy.boundary.arn
}

output "kms_key_id" {
  description = "ID da chave KMS para state encryption"
  value       = aws_kms_key.terraform_state.id
}

# --- 8. AWS Config (Compliance Contínuo) ---
# Monitora a configuração dos recursos e alerta sobre desvios de segurança.

resource "aws_config_configuration_recorder" "main" {
  name     = lower("${var.project_name}-config-recorder")
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_s3_bucket" "config" {
  bucket        = lower("${var.project_name}-config-logs")
  force_destroy = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  bucket = aws_s3_bucket.config.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.terraform_state.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "config" {
  bucket = aws_s3_bucket.config.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket                  = aws_s3_bucket.config.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSConfigBucketPermissionsCheck"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:GetBucketAcl"
        Resource = aws_s3_bucket.config.arn
      },
      {
        Sid    = "AWSConfigBucketDelivery"
        Effect = "Allow"
        Principal = { Service = "config.amazonaws.com" }
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.config.arn}/AWSLogs/*"
        Condition = {
          StringEquals = { "s3:x-amz-acl" = "bucket-owner-full-control" }
        }
      }
    ]
  })
}

resource "aws_sns_topic" "config_compliance" {
  name              = lower("${var.project_name}-config-compliance")
  kms_master_key_id = aws_kms_key.terraform_state.id
}

resource "aws_config_delivery_channel" "main" {
  name           = lower("${var.project_name}-config-delivery")
  s3_bucket_name = aws_s3_bucket.config.bucket
  sns_topic_arn  = aws_sns_topic.config_compliance.arn
  depends_on     = [aws_config_configuration_recorder.main]
}

resource "aws_config_configuration_recorder_status" "main" {
  name       = aws_config_configuration_recorder.main.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.main]
}

resource "aws_iam_role" "config" {
  name = lower("${var.project_name}-config-role")
  permissions_boundary = aws_iam_policy.boundary.arn
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "config.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# --- Regras de Compliance (Guardrails) ---

resource "aws_config_config_rule" "s3_bucket_encryption" {
  name = lower("${var.project_name}-s3-bucket-encryption")
  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}

# --- 9. CloudWatch Alarms & SNS (Monitoramento Ativo) ---
# VULN-002/Melhoria: Alertas em tempo real para e-mail

resource "aws_sns_topic" "security_alerts" {
  name              = lower("${var.project_name}-security-alerts")
  kms_master_key_id = aws_kms_key.terraform_state.id
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alerts.arn
  protocol  = "email"
  endpoint  = var.security_email
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/${lower(var.project_name)}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.terraform_state.arn
}

resource "aws_iam_role" "cloudtrail_cloudwatch" {
  name = lower("${var.project_name}-cloudtrail-cw-role")

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action = "sts:AssumeRole"
    }]
  })
}


resource "aws_iam_role_policy" "cloudtrail_cloudwatch" {
  name = lower("${var.project_name}-cloudtrail-cw-policy")
  role = aws_iam_role.cloudtrail_cloudwatch.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ]
      Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
    }]
  })
}

# Alarme 1: Chamadas de API não autorizadas
resource "aws_cloudwatch_log_metric_filter" "unauthorized_api_calls" {
  name           = lower("${var.project_name}-unauthorized-api-calls")
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"

  metric_transformation {
    name      = "UnauthorizedAPICalls"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "unauthorized_api_calls" {
  alarm_name          = lower("${var.project_name}-unauthorized-api-calls")
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "UnauthorizedAPICalls"
  namespace           = "CloudTrailMetrics"
  period              = 300
  statistic           = "Sum"
  threshold           = 5
  alarm_description   = "Alerta: Multiplas tentativas de acesso nao autorizado detectadas."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}

# Alarme 2: Uso da Conta Root (CRÍTICO - VULN-002)
resource "aws_cloudwatch_log_metric_filter" "root_usage" {
  name           = lower("${var.project_name}-root-usage")
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"

  metric_transformation {
    name      = "RootAccountUsage"
    namespace = "CloudTrailMetrics"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "root_usage" {
  alarm_name          = lower("${var.project_name}-root-usage")
  comparison_operator = "GreaterThanOrEqualToThreshold"
  evaluation_periods  = 1
  metric_name         = "RootAccountUsage"
  namespace           = "CloudTrailMetrics"
  period              = 60
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "ALERTA CRITICO: A conta ROOT foi utilizada! Investigar imediatamente."
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
  treat_missing_data  = "notBreaching"
}

resource "aws_config_config_rule" "iam_permissions_boundary" {
  name = lower("${var.project_name}-iam-permissions-boundary")
  source {
    owner             = "AWS"
    source_identifier = "IAM_ROLE_MANAGED_POLICY_CHECK"
  }
  input_parameters = jsonencode({
    managedPolicyArns = aws_iam_policy.boundary.arn
  })
  depends_on = [aws_config_configuration_recorder.main]
}

resource "aws_config_config_rule" "cloudtrail_enabled" {
  name = lower("${var.project_name}-cloudtrail-enabled")
  source {
    owner             = "AWS"
    source_identifier = "CLOUD_TRAIL_ENABLED"
  }
  depends_on = [aws_config_configuration_recorder.main]
}