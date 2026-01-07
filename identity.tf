# =================================================================================
# The Bridge - Identity Stack
# =================================================================================
# Este arquivo cria a "Ponte" de autenticação entre GitHub Actions e AWS.
# Ele define o OIDC Provider, a Role e as Políticas de Permissão.
# =================================================================================

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
    prevent_destroy = true
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
    prevent_destroy = true
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
          "iam:AttachUserPolicy", "iam:PutUserPolicy", "iam:CreateGroup",
          "iam:DeleteRolePermissionsBoundary", "iam:PutRolePermissionsBoundary"
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
          "arn:aws:iam::*:policy/*-devops-policy",
          "arn:aws:iam::*:role/*-github-actions-role"
        ]
      },
      # 3. ISOLAMENTO: Impede Movimentação Lateral (PassRole) para roles fora do projeto
      {
        Sid         = "DenyPassRoleToExternal"
        Effect      = "Deny"
        Action      = "iam:PassRole"
        NotResource = "arn:aws:iam::*:role/${lower(var.project_name)}-*"
      }
    ]
  })
}

# --- 4. IAM Policy (Permissões do Pipeline) ---
# Define o que o GitHub Actions pode fazer.
# Esta política segue o princípio de Least Privilege mas permite operações de DevOps.
resource "aws_iam_policy" "devops_policy" {
  name        = lower("${var.project_name}-devops-policy")
  description = "Permissoes de CI/CD geradas pelo The Bridge"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # 0. SELF-PROTECTION: Impede que o GitHub Actions edite suas próprias regras para virar Admin
      {
        Sid      = "DenySelfTampering"
        Effect   = "Deny"
        Action   = [
          "iam:DeletePolicy", "iam:DeletePolicyVersion",
          "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"
        ]
        Resource = [
          "arn:aws:iam::*:policy/*-infra-boundary",
          "arn:aws:iam::*:policy/*-devops-policy"
        ]
      },
      # S3 e DynamoDB (Backend Terraform)
      {
        Sid    = "TerraformBackendAccess"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket", "s3:ListBucket", "s3:Get*", "s3:Put*", "s3:DeleteObject",
          "s3:GetBucketVersioning", "s3:PutBucketVersioning", "s3:GetBucketEncryption", "s3:PutBucketEncryption",
          "dynamodb:CreateTable", "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem", "dynamodb:DescribeTable"
        ]
        Resource = [
          "arn:aws:s3:::*-tfstate-bucket",
          "arn:aws:s3:::*-tfstate-bucket/*",
          "arn:aws:dynamodb:*:*:table/*-tf-lock-table"
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
      # Gerenciamento de EC2 e Rede
      {
        Sid    = "EC2Management"
        Effect = "Allow"
        Action = "ec2:*"
        Resource = "*"
      },
      # Gerenciamento de IAM - CRIAÇÃO DE ROLES (Com Restrição de Boundary)
      {
        Sid    = "IAMCreateRoleWithBoundary"
        Effect = "Allow"
        Action = [
          "iam:CreateRole", "iam:PutRolePermissionsBoundary"
        ]
        Resource = "arn:aws:iam::*:role/${lower(var.project_name)}-*"
        # AQUI ESTÁ A SEGURANÇA: Só permite criar role SE anexar a boundary
        Condition = {
          StringEquals = {
            "iam:PermissionsBoundary" = aws_iam_policy.boundary.arn
          }
        }
      },
      # Gerenciamento de IAM - Outras Operações (Restrito ao Escopo do Projeto)
      # EVITA ARMADILHA: Impede que o pipeline altere roles/policies de outros projetos ou faça PassRole de Admins
      {
        Sid    = "IAMManagement"
        Effect = "Allow"
        Action = [
          "iam:DeleteRole", "iam:TagRole", "iam:UntagRole", "iam:UpdateRole",
          "iam:CreateInstanceProfile", "iam:DeleteInstanceProfile", 
          "iam:AddRoleToInstanceProfile", 
          "iam:RemoveRoleFromInstanceProfile", "iam:TagInstanceProfile", "iam:UntagInstanceProfile",
          "iam:CreatePolicy", "iam:DeletePolicy", "iam:CreatePolicyVersion", "iam:DeletePolicyVersion",
          "iam:AttachRolePolicy", "iam:DetachRolePolicy", "iam:PassRole"
        ]
        Resource = [
          "arn:aws:iam::*:role/${lower(var.project_name)}-*",
          "arn:aws:iam::*:instance-profile/${lower(var.project_name)}-*",
          "arn:aws:iam::*:policy/${lower(var.project_name)}-*"
        ]
      },
      # Gerenciamento de ECR
      {
        Sid    = "ECRManagement"
        Effect = "Allow"
        Action = [
          "ecr:CreateRepository", "ecr:DeleteRepository", "ecr:PutImage", "ecr:BatchGetImage",
          "ecr:GetAuthorizationToken", "ecr:SetRepositoryPolicy", "ecr:PutLifecyclePolicy"
        ]
        Resource = "*"
      },
      # Gerenciamento de SSM e Logs
      {
        Sid    = "SSMAndLogs"
        Effect = "Allow"
        Action = [
          "ssm:GetParameter", "ssm:PutParameter", "ssm:DeleteParameter", "ssm:AddTagsToResource",
          "logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:PutRetentionPolicy"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "devops" {
  role       = aws_iam_role.github_actions.name
  policy_arn = aws_iam_policy.devops_policy.arn
}

output "permissions_boundary_arn" {
  description = "ARN da Policy de Permissions Boundary (Use na variável 'PERMISSIONS_BOUNDARY_ARN' do GitHub)."
  value       = aws_iam_policy.boundary.arn
}