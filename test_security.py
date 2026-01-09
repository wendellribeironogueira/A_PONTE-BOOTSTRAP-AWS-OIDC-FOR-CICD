import pytest
import re
import json
import os

IDENTITY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "identity.tf")

def test_permissions_boundary_enforced():
    """Verifica se Permissions Boundary está presente no código"""
    with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    
    assert "aws_iam_policy.boundary" in content, "A definição da Policy de Boundary foi removida!"
    assert "iam:PermissionsBoundary" in content, "A condição de PermissionsBoundary foi removida das Roles!"

def test_no_wildcard_resources_in_dangerous_actions():
    """Verifica se não há 'Action: *' e 'Resource: *' juntos (exceto onde explicitamente permitido)"""
    with open(IDENTITY_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Extrai blocos jsonencode para análise simplificada
    # Nota: Isso é uma verificação estática simples. Ferramentas como tfsec fariam isso melhor.
    policies = re.findall(r'policy = jsonencode\((.*?)\)', content, re.DOTALL)
    
    for policy in policies:
        # Limpeza básica para tentar parsear o JSON (pode falhar se tiver variáveis do Terraform)
        # Aqui focamos em encontrar o padrão de texto perigoso
        if '"Action": "*"' in policy and '"Resource": "*"' in policy:
             # Se encontrar, verificamos se é a boundary (que permite AllowInfrastructure)
             if "AllowInfrastructure" not in policy:
                 pytest.fail("Política perigosa detectada: Action e Resource com wildcard fora da Boundary")