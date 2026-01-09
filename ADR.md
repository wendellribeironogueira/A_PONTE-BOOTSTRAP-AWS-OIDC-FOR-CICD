# Architecture Decision Records (ADR) - A-PONTE

Este documento registra as decisões arquiteturais significativas tomadas no desenvolvimento do projeto **A-PONTE**. O objetivo é fornecer contexto e justificativa para as escolhas técnicas, servindo como guia para contribuidores e usuários, garantindo que o projeto mantenha seus padrões de segurança e governança.

## Índice
1. [ADR-001: Federação de Identidade via OIDC](#adr-001-federação-de-identidade-via-oidc)
2. [ADR-002: Governança via IAM Permissions Boundary](#adr-002-governança-via-iam-permissions-boundary)
3. [ADR-003: Estratégia de Bootstrap Híbrido (The Bridge)](#adr-003-estratégia-de-bootstrap-híbrido-the-bridge)
4. [ADR-004: Deploy Seguro via AWS Systems Manager (No-SSH)](#adr-004-deploy-seguro-via-aws-systems-manager-no-ssh)
5. [ADR-005: Criptografia Gerenciada pelo Cliente (KMS CMK)](#adr-005-criptografia-gerenciada-pelo-cliente-kms-cmk)
6. [ADR-006: Monitoramento Ativo de Segurança](#adr-006-monitoramento-ativo-de-segurança)

---

## ADR-001: Federação de Identidade via OIDC

### Status
Aceito

### Contexto
Para que o GitHub Actions possa provisionar infraestrutura na AWS, ele precisa de credenciais. A abordagem tradicional envolve criar um Usuário IAM, gerar Access Keys de longa duração e armazená-las nos Secrets do GitHub. Isso apresenta riscos de segurança significativos (vazamento de chaves, dificuldade de rotação).

### Decisão
Utilizar **OpenID Connect (OIDC)** para federar a identidade do GitHub Actions diretamente com a AWS.

### Consequências
*   **Positivas:** Elimina a necessidade de chaves de acesso de longa duração. A AWS emite tokens temporários apenas para a execução do workflow. Aumenta drasticamente a segurança e simplifica a gestão de credenciais.
*   **Negativas:** Requer configuração inicial de um Identity Provider na AWS (automatizado pelo script `the_bridge.py`).

---

## ADR-002: Governança via IAM Permissions Boundary

### Status
Aceito

### Contexto
A Role utilizada pelo CI/CD precisa de permissões amplas para criar recursos (EC2, S3, VPC). No entanto, se essa Role for comprometida ou mal configurada, ela poderia ser usada para criar um usuário "Admin" e tomar controle total da conta (Escalação de Privilégio).

### Decisão
Anexar uma **Permissions Boundary** a todas as Roles criadas pelo sistema, incluindo a Role do próprio CI/CD.

### Consequências
*   **Positivas:** Define um "teto máximo" de permissões. Mesmo que a Role tenha `AdministratorAccess`, ela não pode realizar ações bloqueadas pelo Boundary (ex: criar usuários IAM, remover logs de auditoria, alterar o próprio Boundary).
*   **Negativas:** Aumenta a complexidade das políticas de IAM. Requer que toda criação de Role inclua explicitamente o Boundary.

---

## ADR-003: Estratégia de Bootstrap Híbrido (The Bridge)

### Status
Aceito

### Contexto
O Terraform precisa de um Bucket S3 para armazenar seu estado (`terraform.tfstate`) e uma tabela DynamoDB para lock. Além disso, ele precisa de uma Role IAM para executar. No entanto, o Terraform não pode criar esses recursos para si mesmo antes de existir (o problema do "Ovo e a Galinha").

### Decisão
Desenvolver um script Python (`the_bridge.py`) que atua como um orquestrador de Bootstrap. Ele utiliza credenciais locais temporárias para criar a fundação (Identidade + State Backend) e, em seguida, importa esses recursos para o estado do Terraform.

### Consequências
*   **Positivas:** Automatiza completamente o setup inicial. Garante que a infraestrutura base seja gerenciada como código (IaC) após a criação. Implementa "Self-Healing" (importa recursos se já existirem).
*   **Negativas:** Introduz uma dependência de Python e Boto3 para a execução inicial.

---

## ADR-004: Deploy Seguro via AWS Systems Manager (No-SSH)

### Status
Aceito

### Contexto
O acesso a servidores EC2 para deploy de aplicações geralmente é feito via SSH (Porta 22). Isso exige gerenciamento de chaves SSH (`.pem`), exposição de portas para a internet (ou uso de Bastion Hosts) e rotação de chaves.

### Decisão
Utilizar o **AWS Systems Manager (SSM) Run Command** para orquestrar deploys e o **Session Manager** para acesso interativo.

### Consequências
*   **Positivas:** A porta 22 pode permanecer fechada no Security Group. Não há chaves SSH para gerenciar ou vazar. Todas as sessões e comandos são auditados no CloudTrail e S3.
*   **Negativas:** Exige que o Agente SSM esteja instalado e rodando nas instâncias (padrão na Amazon Linux 2/2023).

---

## ADR-005: Criptografia Gerenciada pelo Cliente (KMS CMK)

### Status
Aceito

### Contexto
Dados sensíveis no arquivo de estado do Terraform e logs de auditoria precisam de proteção robusta. A criptografia padrão do S3 (SSE-S3) é gerida pela AWS e não oferece controle granular sobre quem pode descriptografar os dados.

### Decisão
Utilizar **AWS KMS Customer Managed Keys (CMK)** para criptografar o Bucket de Estado e Logs.

### Consequências
*   **Positivas:** Controle total sobre a chave (rotação, política de acesso). Permite auditoria de uso da chave via CloudTrail. Compliance com normas bancárias/enterprise.
*   **Negativas:** Custo adicional por chave KMS ativa e por requisições de criptografia/descriptografia.

---

## ADR-006: Monitoramento Ativo de Segurança

### Status
Aceito

### Contexto
Apenas registrar logs (CloudTrail) não é suficiente; é necessário reagir a eventos críticos em tempo real para evitar danos maiores.

### Decisão
Implementar **AWS Config** para conformidade contínua e **CloudWatch Alarms** integrados ao **SNS** para notificação imediata de atividades suspeitas (ex: chamadas de API não autorizadas).

### Consequências
*   **Positivas:** Reduz o tempo de resposta a incidentes (MTTR). Garante que desvios de configuração (ex: bucket público) sejam detectados.
*   **Negativas:** Pode gerar ruído (alert fatigue) se os limiares de alarme não forem bem ajustados.