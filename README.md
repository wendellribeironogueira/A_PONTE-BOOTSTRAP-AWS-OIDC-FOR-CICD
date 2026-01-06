# 🌉 A PONTE (The Bridge) - AWS Bootstrap & OIDC Identity Broker

> **Nível de Maturidade:** Production-Ready / Senior DevSecOps Tool
> **Foco:** Segurança (Zero Long-Lived Credentials), Automação, Self-Healing e Compliance.

**A PONTE** é uma ferramenta de engenharia de infraestrutura projetada para resolver o **Bootstrap Paradox** (Ovo e Galinha) na AWS. Ela provisiona a camada de identidade federada necessária para que pipelines de CI/CD (GitHub Actions) possam gerenciar infraestrutura via Terraform sem armazenar credenciais estáticas (Access Keys) sensíveis.

---

##  Arquitetura de Segurança (Cybersecurity Deep Dive)

```mermaid
graph TD
    subgraph CI_CD [GitHub Ecosystem]
        GHA[GitHub Actions Runner]
        JWT_S[OIDC Token Service]
    end

    subgraph AWS [AWS Account]
        subgraph Identity_Layer [Identity & Access Management]
            OIDC_P[AWS OIDC Provider]
            STS[AWS STS]
            
            subgraph Role_Construct [IAM Role: *-github-actions-role]
                TP["Trust Policy<br/>(Condition: repo:user/repo:*)"]
                P_DevOps["Policy: *-devops-policy<br/>(Least Privilege)"]
            end
            
            PB["Permissions Boundary: *-infra-boundary<br/>(The 'Glass Ceiling')"]
        end

        subgraph Infrastructure [Managed Resources]
            TF_State[S3/DynamoDB State]
            Compute[EC2 / ECR / VPC]
            IAM_New[New IAM Roles]
        end
    end

    %% Flows
    GHA -- "1. Request ID Token" --> JWT_S
    JWT_S -- "2. Sign JWT (sub: repo:...)" --> GHA
    GHA -- "3. AssumeRoleWithWebIdentity (JWT)" --> STS
    STS -- "4. Verify Signature & Audience" --> OIDC_P
    STS -- "5. Validate Trust Condition (StringLike)" --> TP
    STS -- "6. Return Temp Credentials" --> GHA
    
    GHA -- "7. Terraform Apply" --> Infrastructure
    
    %% Relationships & Security Controls
    TP -.-> |Protects| Role_Construct
    P_DevOps --> |Allows| Infrastructure
    PB -.-> |RESTRICTS (Max Permissions)| Role_Construct
    PB -.-> |RESTRICTS (Inheritance)| IAM_New
    
    %% Styling
    classDef security fill:#ffcccc,stroke:#ff0000,stroke-width:2px;
    classDef component fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
    
    class PB,TP security;
    class GHA,STS,OIDC_P component;
```

A segurança desta ferramenta baseia-se no padrão **OpenID Connect (OIDC)** e em **Permissions Boundaries**, eliminando a necessidade de usuários IAM e mitigando riscos de escalação de privilégios.

### 1. Federação de Identidade (Web Identity Federation)
Em vez de credenciais, estabelecemos uma relação de confiança entre o Provedor de Identidade do GitHub (`token.actions.githubusercontent.com`) e o AWS STS.

*   **Fluxo de Autenticação:**
    1.  O GitHub Actions solicita um JWT assinado pelo GitHub.
    2.  Envia o token para a AWS (`sts:AssumeRoleWithWebIdentity`).
    3.  A AWS valida a assinatura e a **Condition Key** `sub` (Subject).
    4.  Retorna credenciais temporárias para a Role.

### 2. IAM Role & Trust Policy (A "Fechadura")
A Role criada (`*-github-actions-role`) possui uma **Trust Policy** rigorosa:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/..." },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringLike": {
      "token.actions.githubusercontent.com:sub": "repo:SEU_USUARIO/SEU_REPO:*"
    }
  }
}
```
*   **Segurança:** A condição `StringLike` garante que **apenas** workflows do repositório especificado podem assumir esta role.

### 3. Permissions Boundary (O "Teto de Vidro") 
Para mitigar o risco de **Privilege Escalation**, todas as Roles criadas por esta ferramenta (e pelo Terraform subsequente) são restritas por uma **Permissions Boundary** (`*-infra-boundary`).

*   **Bloqueio de IAM:** Impede a criação de usuários IAM, Login Profiles ou Access Keys (evita Backdoors).
*   **Self-Protection:** Impede que a Role delete ou modifique a própria Boundary ou as Policies de segurança do Bootstrap.
*   **Compliance Forçado:** O Terraform só consegue criar novas Roles (ex: para EC2) se anexar esta Boundary a elas. Caso contrário, a AWS nega a criação (`AccessDenied`).

### 4. IAM Policy (O "Escopo de Acesso")
A política operacional (`*-devops-policy`) segue o princípio de **Privilégio Mínimo Viável para IaC**.

| Categoria | Permissões | Justificativa Técnica |
| :--- | :--- | :--- |
| **Terraform Backend** | `s3`, `dynamodb` | Restrito aos recursos de estado (`*-tfstate-bucket`, `*-tf-lock-table`). |
| **Compute & Network** | `ec2:*`, `ecr:*` | Provisionamento de infraestrutura. |
| **IAM Management** | `iam:CreateRole`, etc. | Permitido apenas se a **Permissions Boundary** for anexada. |

---

## 🛠️ Engenharia do Script (`the_bridge.py`)

O orquestrador Python implementa lógicas avançadas de segurança e resiliência.

### Funcionalidades Avançadas:
1.  **Input Sanitization (Anti-Injection):**
    *   Todos os inputs (Projeto, Região, Repo) passam por validação rigorosa de Regex (`^[a-zA-Z0-9-]+$`) antes de serem usados em comandos de shell, prevenindo **Command Injection**.

2.  **Bypass de Variáveis de Ambiente (Windows Safe):**
    *   Gera dinamicamente um arquivo `terraform.tfvars.json` efêmero para garantir a injeção correta de variáveis complexas em ambientes Windows.

3.  **Self-Healing (Auto-Cura):**
    *   Verifica a existência de recursos via Boto3/CLI e executa `terraform import` automaticamente se necessário, garantindo idempotência.

---

## 🚀 Guia de Uso (Operacional)

### Pré-requisitos
*   Python 3.x
*   Terraform >= 1.0
*   AWS CLI (configurado com `AdministratorAccess` apenas para o bootstrap).

### Execução
**Modo Interativo:**
```bash
python the_bridge.py
```

**Modo Batch (Automação):**
```bash
python the_bridge.py --batch --project-name "Prod" --aws-region "us-east-1" --github-repo "org/infra-core"
```

### Pós-Execução (Integração CI/CD)
Ao final da execução, o script exibirá um **Guia de Integração**. Você deve configurar dois valores no seu repositório GitHub para permitir que o pipeline funcione.

Acesse: **Settings > Secrets and variables > Actions**

#### 1. Aba "Secrets" (Segredos)
Crie um **New repository secret**:
*   **Nome:** `AWS_ROLE_TO_ASSUME`
*   **Valor:** O ARN da Role exibido pelo script (ex: `arn:aws:iam::123456789012:role/prod-github-actions-role`).

#### 2. Aba "Variables" (Variáveis)
Crie uma **New repository variable**:
*   **Nome:** `PERMISSIONS_BOUNDARY_ARN`
*   **Valor:** O ARN da Boundary exibido pelo script (ex: `arn:aws:iam::123456789012:policy/prod-infra-boundary`).
    *   *Nota: Isso é obrigatório para que o Terraform possa criar novas Roles (ex: EC2) em conformidade com as regras de segurança.*

---

## ⚠️ Matriz de Riscos & Mitigações

| Risco | Severidade | Mitigação Implementada |
| :--- | :--- | :--- |
| **Privilege Escalation** | Crítica | **Permissions Boundary:** Bloqueia criação de Users e edição de Policies críticas. |
| **Command Injection** | Alta | **Input Sanitization:** Regex estrito no script Python. |
| **Lockout (Delete Acidental)** | Alta | **Lifecycle Prevent Destroy:** Terraform impede destruição de recursos de identidade. |
| **Confused Deputy** | Média | **Trust Policy Condition:** Validação estrita do `sub` (Repo) do GitHub. |

---
*Developed for High-Performance DevSecOps Environments.*