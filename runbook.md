# Runbook Operacional - A-PONTE

Este documento descreve procedimentos para resolução de problemas comuns e cenários de recuperação de desastres.

## 🚨 Cenários de Incidente

### 1. Falha no Bootstrap ("Resource Already Exists")
**Sintoma:** O script `the_bridge.py` falha com erro indicando que a Role ou Bucket já existe.
**Causa:** O recurso foi criado manualmente ou por uma execução anterior que falhou antes de atualizar o estado.
**Solução:**
1. Identifique o recurso conflitante no console AWS.
2. Importe-o manualmente para o Terraform:
   ```bash
   terraform import aws_iam_role.github_actions nome-da-role-existente
   ```
3. Re-execute `python the_bridge.py`.

### 2. Pipeline Falhando com "Access Denied"
**Sintoma:** O GitHub Actions não consegue criar recursos (ex: EC2).
**Diagnóstico:**
1. Verifique se a Role tem o **Permissions Boundary** anexado:
   ```bash
   aws iam get-role --role-name NOME_DA_ROLE --query 'Role.PermissionsBoundary'
   ```
2. Se não tiver, a criação foi bloqueada pela SCP ou Boundary da Role de Deploy.
**Solução:**
Certifique-se de que seu código Terraform (`main.tf`) inclui:
```hcl
permissions_boundary = var.permissions_boundary
```

### 3. Alerta de Uso da Conta Root
**Sintoma:** E-mail recebido com assunto "ALERTA CRITICO: A conta ROOT foi utilizada!".
**Ação Imediata:**
1. **Logue na AWS** imediatamente e verifique o CloudTrail para identificar a origem (IP, User Agent).
2. **Rotacione a senha** de root se houver suspeita de comprometimento.
3. **Verifique MFA**: A conta root deve ter MFA físico ou virtual habilitado.

## 🛠️ Manutenção

### Rotação de Chaves KMS
As chaves KMS criadas pelo A-PONTE têm rotação automática anual habilitada. Nenhuma ação manual é necessária.

### Atualização do aws-nuke
Ao atualizar a versão do `aws-nuke` no script de limpeza, você **DEVE** atualizar o hash SHA256 no script `nuke-cleanup.ps1` para evitar bloqueio de segurança.