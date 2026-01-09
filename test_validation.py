import pytest
import sys
import os

# Adiciona o diretório pai ao path para importar o the_bridge
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from the_bridge import validate_input

def test_project_name_valid():
    """Testa se nomes válidos passam"""
    # validate_input encerra o programa com sys.exit(1) se falhar, então se não lançar exceção, passou.
    validate_input("prod-app", r"^[a-zA-Z0-9-]+$", "project")

def test_project_name_injection():
    """Testa se command injection é bloqueado"""
    with pytest.raises(SystemExit):
        validate_input("prod; rm -rf /", r"^[a-zA-Z0-9-]+$", "project")

def test_github_repo_valid():
    """Testa formato de repositório GitHub"""
    validate_input("user/repo", r"^[a-zA-Z0-9-_\/]+$", "repo")

def test_github_repo_wildcard():
    """Testa se caracteres inválidos são bloqueados"""
    with pytest.raises(SystemExit):
        validate_input("user/*", r"^[a-zA-Z0-9-_\/]+$", "repo")

def test_aws_region_valid():
    """Testa regiões AWS válidas"""
    validate_input("sa-east-1", r"^[a-z0-9-]+$", "region")