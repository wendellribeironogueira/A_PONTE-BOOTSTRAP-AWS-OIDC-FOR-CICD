variable "project_name" {
  description = "Nome do projeto para prefixar recursos."
  type        = string
}

variable "aws_region" {
  description = "Região AWS onde os recursos serão criados."
  type        = string
}

variable "github_repos" {
  description = "Lista de repositórios GitHub autorizados (ex: 'usuario/repo' ou 'usuario/*')."
  type        = list(string)
}

variable "tags" {
  description = "Tags padrão para aplicar aos recursos."
  type        = map(string)
  default     = {
    Tool      = "The Bridge"
    ManagedBy = "Terraform"
  }
}