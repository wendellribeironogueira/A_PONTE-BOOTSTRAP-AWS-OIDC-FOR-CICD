output "role_arn" {
  description = "ARN da Role criada. Configure isso no seu GitHub Secrets (AWS_ROLE_TO_ASSUME)."
  value       = aws_iam_role.github_actions.arn
}

output "oidc_provider_arn" {
  description = "ARN do OIDC Provider."
  value       = aws_iam_openid_connect_provider.github.arn
}