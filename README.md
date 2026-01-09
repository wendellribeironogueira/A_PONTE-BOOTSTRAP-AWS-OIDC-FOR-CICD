# A-PONTE 🌉
**Automated Provisioning & Operations for New Technical Environments**

> "De quem veio do Data Center para quem quer dominar o DevOps."

!AWS
!Terraform
!Python
!Security

## 📖 Sobre o Projeto
**A-PONTE** é um acelerador de infraestrutura (Boilerplate) "Enterprise-Grade" para AWS. Ele foi desenhado para resolver o problema do "Ovo e a Galinha" na automação de infraestrutura: como criar uma pipeline segura se você ainda não tem a infraestrutura de segurança (IAM, Buckets, OIDC) criada?

Este projeto nasceu de estudos pessoais e da transição de carreira de Infraestrutura Tradicional (Data Center) para DevOps. O objetivo é democratizar o acesso a configurações de segurança avançadas que geralmente ficam restritas a grandes corporações, permitindo que qualquer pessoa inicie um ambiente AWS seguro, auditável e automatizado em minutos.

## 🚀 Diferenciais (Enterprise Grade)
O que torna este projeto diferente de um "Hello World" em Terraform?

*   **Zero Access Keys:** Autenticação via OIDC (GitHub <-> AWS). Nenhuma chave de acesso permanente é armazenada ou trafegada.
*   **Governança de IAM:** Implementação de *Permissions Boundaries* para impedir escalação de privilégios (o CI/CD não pode criar um usuário Admin).
*   **Criptografia Bancária:** Uso de chaves KMS gerenciadas pelo cliente (CMK) para criptografar o estado do Terraform e Logs.
*   **Compliance Contínuo:** Regras do AWS Config ativas desde o dia 0 para monitorar segurança.
*   **Auditoria Total:** CloudTrail e Logs de Acesso S3 habilitados e centralizados.
*   **Deploy Seguro:** Uso do AWS Systems Manager (SSM) para evitar abertura de porta SSH (22).

## 📚 Documentação de Arquitetura (ADR)
Todas as decisões técnicas importantes foram documentadas seguindo o padrão **Architecture Decision Records (ADR)**. Isso explica o "porquê" por trás do código.

👉 Leia os ADRs aqui

## 🛠️ Como Usar

### Pré-requisitos
*   Python 3.x instalado.
*   AWS CLI configurado (`aws configure`) com credenciais administrativas (apenas para o bootstrap inicial).
*   Terraform instalado.

### Passo a Passo
1.  Clone o repositório.
2.  Navegue até a pasta do projeto.
3.  Execute o script de bootstrap:
    ```bash
    python the_bridge.py
    ```
4.  Siga as instruções interativas no terminal. O script irá:
    *   Criar a identidade OIDC.
    *   Criar o Bucket S3 e DynamoDB para o Terraform.
    *   Configurar chaves KMS e CloudTrail.
    *   Importar tudo para o estado do Terraform.

### Pós-Instalação
Ao final da execução, o script fornecerá os valores de `AWS_ROLE_TO_ASSUME` e `PERMISSIONS_BOUNDARY_ARN` para você configurar nos Secrets/Variables do seu repositório GitHub.

## 🤝 Contribuição
Este projeto é Open Source! Sinta-se à vontade para abrir Issues, enviar PRs ou sugerir melhorias. O objetivo é aprendermos juntos.

## ⚠️ Aviso de Custos
Este projeto cria recursos na AWS que podem gerar custos (KMS Keys, Config Rules, NAT Gateways se configurado). Lembre-se de destruir a infraestrutura (`terraform destroy`) quando não estiver usando para evitar cobranças.

---
*Desenvolvido com ❤️ e Muito Café.*