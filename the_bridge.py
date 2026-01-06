import os
import sys
import subprocess
import argparse
import re
import shutil
import json

# Configuração de cores para terminal (ANSI escape codes)
GRAY = "\033[90m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

def run_command(command, shell=True, check=True, capture_output=False):
    """Executa um comando no shell."""
    try:
        result = subprocess.run(
            command,
            shell=shell,
            check=check,
            text=True,
            capture_output=capture_output,
            env=os.environ.copy()
        )
        return result
    except subprocess.CalledProcessError as e:
        if not capture_output:
             # Se não estiver capturando, o erro provavelmente já foi impresso no stderr
             pass
        raise e

def get_input(prompt, default):
    """Solicita input do usuário com valor padrão."""
    try:
        user_input = input(f"{CYAN}{prompt} [{default}]: {RESET}")
        return user_input.strip() if user_input.strip() else default
    except KeyboardInterrupt:
        print(f"\n{RED}Operação cancelada pelo usuário.{RESET}")
        sys.exit(1)

def validate_input(value, pattern, field_name):
    """Valida se o input corresponde ao padrão regex seguro."""
    if not re.match(pattern, value):
        print(f"{RED}ERRO DE SEGURANÇA: O campo '{field_name}' contém caracteres inválidos ou perigosos.{RESET}")
        print(f"{YELLOW}Valor rejeitado: {value}{RESET}")
        print(f"{YELLOW}Padrão aceito: {pattern}{RESET}")
        sys.exit(1)

def main():
    # Parsing de argumentos similar ao param() do PowerShell
    parser = argparse.ArgumentParser(description="The Bridge - Bootstrap Script (Python Version)")
    parser.add_argument("--project-name", help="Nome do Projeto")
    parser.add_argument("--aws-region", help="Região AWS")
    parser.add_argument("--github-repo", help="Repositório GitHub")
    parser.add_argument("--batch", action="store_true", help="Modo não interativo (usa defaults)")
    args = parser.parse_args()

    # Defaults
    def_project = "First-Run"
    def_region = "sa-east-1"
    def_repo = "seu-usuario/seu-repo"

    # Força UTF-8 no Windows
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")

    print(f"{GRAY}--- INICIANDO A PONTE - THE BRIDGE ---{RESET}")

    # --- INTERATIVIDADE ---
    if not args.batch:
        print(f"{YELLOW}--- CONFIGURAÇÃO INTERATIVA ---{RESET}")
        print(f"{GRAY}(Pressione ENTER para aceitar o valor padrão){RESET}")
        
        project_name = args.project_name if args.project_name else get_input("Nome do Projeto", def_project)
        aws_region = args.aws_region if args.aws_region else get_input("Região AWS", def_region)
        github_repo = args.github_repo if args.github_repo else get_input("Repositório GitHub (ex: user/repo)", def_repo)
    else:
        project_name = args.project_name if args.project_name else def_project
        aws_region = args.aws_region if args.aws_region else def_region
        github_repo = args.github_repo if args.github_repo else def_repo

    # --- VALIDAÇÃO DE SEGURANÇA (INPUT SANITIZATION) ---
    # Previne Command Injection via shell=True
    validate_input(project_name, r"^[a-zA-Z0-9-]+$", "Nome do Projeto")
    validate_input(aws_region, r"^[a-z0-9-]+$", "Região AWS")
    validate_input(github_repo, r"^[a-zA-Z0-9-_\/\*]+$", "Repositório GitHub")
    
    # 1. Verificacao de Credenciais
    print(f"{GRAY}--- VERIFICANDO CREDENCIAIS AWS ---{RESET}")

    # Força a região para a sessão atual
    os.environ["AWS_REGION"] = aws_region
    os.environ["AWS_DEFAULT_REGION"] = aws_region

    try:
        res = run_command("aws sts get-caller-identity --output json", capture_output=True)
        identity = json.loads(res.stdout)
        print(f"{GRAY}Conectado como: {identity.get('Arn')}{RESET}")
    except Exception:
        print(f"{RED}ERRO: Nao foi possivel autenticar na AWS. Execute 'aws configure'.{RESET}")
        sys.exit(1)

    print("")
    print(f"{CYAN}--- INICIANDO BOOTSTRAP (MODO LOCAL) ---{RESET}")
    
    # Garante que o script execute no diretório onde estão os arquivos .tf
    script_dir = os.path.dirname(os.path.abspath(__file__))
    os.chdir(script_dir)

    # DETECCAO DE TFVARS (Prioridade sobre parametros do script)
    tfvars_path = "terraform.tfvars"
    if os.path.exists(tfvars_path):
        print(f"{YELLOW}⚠️  Arquivo 'terraform.tfvars' encontrado. Seus valores terao prioridade.{RESET}")
        try:
            with open(tfvars_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Regex equivalente ao do PowerShell: 'project_name\s*=\s*"([^"]+)"'
            match = re.search(r'project_name\s*=\s*"([^"]+)"', content)
            if match:
                project_name = match.group(1)
                print(f"{CYAN}   > Atualizando project_name do script para: {project_name}{RESET}")
        except Exception as e:
            print(f"{YELLOW}   > Erro ao ler terraform.tfvars: {e}{RESET}")

    print(f"Projeto: {project_name}")
    print(f"Regiao:  {aws_region}")
    print(f"Repo:    {github_repo}")

    # 2. Gerar arquivo de variáveis (Bypass de Env Vars)
    print(f"{GRAY}Gerando terraform.tfvars.json temporário...{RESET}")
    with open("terraform.tfvars.json", "w", encoding="utf-8") as f:
        json.dump({
            "project_name": project_name,
            "aws_region": aws_region,
            "github_repos": [github_repo]
        }, f, indent=2)

    # 3. Executa Terraform
    # Limpeza de cache
    if os.path.exists(".terraform"):
        try:
            shutil.rmtree(".terraform")
        except Exception as e:
            print(f"{YELLOW}Aviso: Não foi possível remover .terraform: {e}{RESET}")
            
    if os.path.exists(".terraform.lock.hcl"):
        try:
            os.remove(".terraform.lock.hcl")
        except Exception as e:
            print(f"{YELLOW}Aviso: Não foi possível remover .terraform.lock.hcl: {e}{RESET}")

    print(f"{GRAY}Inicializando Terraform...{RESET}")
    try:
        run_command("terraform init -reconfigure")

        # --- 3.1 SELF-HEALING: Importar recursos existentes ---
        print(f"{YELLOW}--- VERIFICANDO ESTADO (SELF-HEALING) ---{RESET}")
        account_id = identity.get("Account")

        def check_and_import(tf_resource, aws_check_cmd, import_id):
            """Verifica se o recurso existe na AWS e importa para o Terraform se necessário."""
            # 1. Verifica se já está no state local
            try:
                state_list = run_command("terraform state list", capture_output=True).stdout
                if tf_resource in state_list:
                    return # Já está gerenciado, segue o baile
            except:
                pass 

            # 2. Verifica se existe na AWS
            try:
                run_command(aws_check_cmd, capture_output=True)
                exists_in_aws = True
            except subprocess.CalledProcessError:
                exists_in_aws = False
            
            # 3. Importa
            if exists_in_aws:
                print(f"{CYAN}   [IMPORT] {tf_resource} já existe na AWS. Importando...{RESET}")
                try:
                    run_command(f"terraform import -var-file=terraform.tfvars.json {tf_resource} {import_id}")
                    print(f"{GREEN}   Sucesso!{RESET}")
                except subprocess.CalledProcessError:
                    print(f"{RED}   Falha ao importar {tf_resource}.{RESET}")

        # OIDC Provider (ID = ARN)
        oidc_arn = f"arn:aws:iam::{account_id}:oidc-provider/token.actions.githubusercontent.com"
        check_and_import("aws_iam_openid_connect_provider.github", f"aws iam get-open-id-connect-provider --open-id-connect-provider-arn {oidc_arn}", oidc_arn)

        # IAM Role (ID = Name)
        role_name_check = f"{project_name.lower()}-github-actions-role"
        check_and_import("aws_iam_role.github_actions", f"aws iam get-role --role-name {role_name_check}", role_name_check)

        # IAM Policy Boundary
        boundary_arn = f"arn:aws:iam::{account_id}:policy/{project_name.lower()}-infra-boundary"
        check_and_import("aws_iam_policy.boundary", f"aws iam get-policy --policy-arn {boundary_arn}", boundary_arn)

        # IAM Policy (ID = ARN)
        policy_arn = f"arn:aws:iam::{account_id}:policy/{project_name.lower()}-devops-policy"
        check_and_import("aws_iam_policy.devops_policy", f"aws iam get-policy --policy-arn {policy_arn}", policy_arn)

        # IAM Role Policy Attachment (ID = role-name/policy-arn)
        # Importante: Importar o anexo evita o erro "Cannot delete a policy attached to entities"
        attachment_id = f"{role_name_check}/{policy_arn}"
        try:
            # Verifica manualmente se a policy está anexada (aws cli retorna lista vazia, não erro, se não estiver)
            res_attach = run_command(f"aws iam list-attached-role-policies --role-name {role_name_check} --output json", capture_output=True)
            attached_pols = json.loads(res_attach.stdout).get("AttachedPolicies", [])
            if any(p['PolicyArn'] == policy_arn for p in attached_pols):
                 state_list = run_command("terraform state list", capture_output=True).stdout
                 if "aws_iam_role_policy_attachment.devops" not in state_list:
                     print(f"{CYAN}   [IMPORT] aws_iam_role_policy_attachment.devops já existe. Importando...{RESET}")
                     run_command(f"terraform import -var-file=terraform.tfvars.json aws_iam_role_policy_attachment.devops {attachment_id}")
                     print(f"{GREEN}   Sucesso!{RESET}")
        except Exception:
            pass # Ignora erros de verificação (ex: role ainda não existe)
        
        # Targets específicos para a PONTE
        targets = [
            "-target=aws_iam_openid_connect_provider.github",
            "-target=aws_iam_role.github_actions",
            "-target=aws_iam_policy.boundary",
            "-target=aws_iam_policy.devops_policy",
            "-target=aws_iam_role_policy_attachment.devops"
        ]
        
        # Monta comando apply
        cmd_str = "terraform apply -auto-approve " + " ".join(targets)
        run_command(cmd_str)

    except subprocess.CalledProcessError:
        print(f"{RED}Erro na execução do Terraform.{RESET}")
        # Limpa variáveis antes de sair
        if os.path.exists("terraform.tfvars.json"):
            os.remove("terraform.tfvars.json")
        sys.exit(1)

    # 4. Limpa Variaveis
    if os.path.exists("terraform.tfvars.json"):
        os.remove("terraform.tfvars.json")

    # 5. Validacao (Prova Real)
    print("")
    print(f"{YELLOW}--- VALIDANDO RECURSOS NA AWS ---{RESET}")

    role_name = f"{project_name.lower()}-github-actions-role"

    # Verifica OIDC Provider
    try:
        res = run_command("aws iam list-open-id-connect-providers --output text", capture_output=True)
        if "token.actions.githubusercontent.com" in res.stdout:
            print(f"{GREEN}[OK] OIDC Provider Confirmado{RESET}")
        else:
            print(f"{YELLOW}[ERRO] OIDC Provider NAO encontrado{RESET}")
    except Exception:
        print(f"{YELLOW}[ERRO] Falha ao listar OIDC Providers{RESET}")

    # Verifica Role
    try:
        # 2>&1 no PowerShell redireciona erro, aqui capture_output=True pega stderr
        run_command(f"aws iam get-role --role-name {role_name}", capture_output=True)
        print(f"{GREEN}[OK] IAM Role Confirmada: {role_name}{RESET}")
    except subprocess.CalledProcessError:
        print(f"{YELLOW}[ERRO] IAM Role NAO encontrada: {role_name}{RESET}")
        print(f"{YELLOW}Dica: Verifique se o Terraform usou um nome diferente (ex: via terraform.tfvars).{RESET}")

    # --- GUIA DE INTEGRAÇÃO ---
    print("")
    print(f"{CYAN}--- GUIA DE INTEGRAÇÃO (PRÓXIMOS PASSOS) ---{RESET}")
    try:
        # Captura os outputs do Terraform em formato JSON para parsing seguro
        out_proc = run_command("terraform output -json", capture_output=True)
        outputs = json.loads(out_proc.stdout)
        
        # Recupera valores (com fallback caso o output não exista)
        p_boundary = outputs.get("permissions_boundary_arn", {}).get("value", "N/A")
        # Tenta 'role_arn' (padrão atual) ou 'github_actions_role_arn' (padrão backend)
        role_arn = outputs.get("role_arn", {}).get("value")
        if not role_arn:
            role_arn = outputs.get("github_actions_role_arn", {}).get("value", "N/A")

        clean_repo = github_repo.replace("/*", "").replace("*", "")
        
        print(f"Acesse: https://github.com/{clean_repo}/settings/secrets/actions")
        print(f"Configure as seguintes credenciais:\n")
        
        print(f"{YELLOW}1. SECRET (Segredo){RESET}")
        print(f"   Nome:  {GREEN}AWS_ROLE_TO_ASSUME{RESET}")
        print(f"   Valor: {role_arn}")
        print("")
        print(f"{YELLOW}2. VARIABLE (Variável de Ambiente){RESET}")
        print(f"   Nome:  {GREEN}PERMISSIONS_BOUNDARY_ARN{RESET}")
        print(f"   Valor: {p_boundary}")
        
    except Exception as e:
        print(f"{RED}Erro ao gerar guia de integração: {e}{RESET}")

    print("")
    print(f"{GREEN}--- CONCLUIDO ---{RESET}")

if __name__ == "__main__":
    main()