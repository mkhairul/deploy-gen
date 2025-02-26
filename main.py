import typer
from typing import Optional, Literal
from enum import Enum
import os
import requests
import json
from pathlib import Path
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import subprocess
import sys
import shutil

app = typer.Typer(help="Behold! The mighty deploy-gen! Let me generate deploy yaml files for you!")

class OutputFormat(str, Enum):
    JSON = "json"
    TEXT = "text"
    TABLE = "table"

class RepoValueType(str, Enum):
    SECRET = "secret"
    VARIABLE = "variable"

# Config directory for storing credentials
CONFIG_DIR = Path.home() / ".deploy-gen"
GITHUB_TOKEN_FILE = CONFIG_DIR / "github_token.json"


def is_npm_package_installed(package_name: str) -> bool:
    """Check if an npm package is installed globally."""
    # Check if npm is available
    if not shutil.which("npm"):
        typer.echo("npm is not installed or not in PATH.")
        return False
    
    try:
        # Run 'npm list -g' and check if the package is in the output
        result = subprocess.run(
            ["npm", "list", "-g", package_name], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            check=False  # Don't raise exception on non-zero exit
        )
        
        # If the package is not found, npm will return a non-zero exit code
        # and the output will contain "empty" or not contain the package name
        return package_name in result.stdout and "empty" not in result.stdout
    except Exception as e:
        typer.echo(f"Error checking for npm package: {e}")
        return False


def check_repomix_installed():
    """Check if repomix npm package is installed and install it if not."""
    if not is_npm_package_installed("repomix"):
        typer.echo("Repomix npm package is not installed. This package is required for some functionality.")
        install = typer.confirm("Would you like to install it globally now?")
        if install:
            try:
                typer.echo("Installing repomix globally...")
                subprocess.check_call(["npm", "install", "-g", "repomix"])
                typer.echo("Repomix installed successfully!")
                return True
            except subprocess.CalledProcessError as e:
                typer.echo(f"Failed to install repomix: {e}")
                typer.echo("Please install it manually with 'npm install -g repomix'.")
                return False
        else:
            typer.echo("Some functionality may be limited without repomix.")
            return False
    return True


@app.command()
def hello(name: str = typer.Argument(..., help="The name to greet"),
          count: int = typer.Option(1, "--count", "-c", help="Number of times to greet"),
          formal: bool = typer.Option(False, "--formal", "-f", help="Use formal greeting")):
    """
    Greet the user with a simple hello message.
    """
    greeting = "Hello" if not formal else "Greetings"
    for _ in range(count):
        typer.echo(f"{greeting}, {name}!")


@app.command()
def info(verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose output")):
    """
    Display information about the application.
    """
    typer.echo("This is a simple CLI application built with Typer.")
    if verbose:
        typer.echo("Typer is a library for building CLI applications with Python.")
        typer.echo("It's based on Click and uses type hints to define commands and options.")


@app.command()
def export(
    file: typer.FileTextWrite = typer.Argument(..., help="File to export data to"),
    format: OutputFormat = typer.Option(OutputFormat.TEXT, "--format", "-f", help="Output format"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Suppress output")
):
    """
    Export data to a file in the specified format.
    """
    data = "Sample data for export"
    
    if format == OutputFormat.JSON:
        import json
        file.write(json.dumps({"data": data}))
    elif format == OutputFormat.TABLE:
        file.write(f"+{'-'*20}+\n")
        file.write(f"| {data.ljust(18)} |\n")
        file.write(f"+{'-'*20}+\n")
    else:  # TEXT format
        file.write(data)
    
    if not quiet:
        typer.echo(f"Data exported to {file.name} in {format.value} format")


@app.command()
def github_auth(
    token: str = typer.Option(..., "--token", help="GitHub Personal Access Token", prompt=True, hide_input=True),
    force: bool = typer.Option(False, "--force", "-f", help="Force overwrite existing token"),
    verify: bool = typer.Option(True, "--verify/--no-verify", help="Verify token with GitHub API")
):
    """
    Authenticate with GitHub using a personal access token.
    
    The token will be stored securely in your user directory for future use.
    Create a token at https://github.com/settings/tokens with appropriate scopes.
    """
    # Create config directory if it doesn't exist
    CONFIG_DIR.mkdir(exist_ok=True, parents=True)
    
    # Check if token already exists
    if GITHUB_TOKEN_FILE.exists() and not force:
        typer.echo("GitHub token already exists. Use --force to overwrite.")
        return
    
    # Verify token if requested
    if verify:
        typer.echo("Verifying token with GitHub API...")
        headers = {"Authorization": f"token {token}"}
        response = requests.get("https://api.github.com/user", headers=headers)
        
        if response.status_code != 200:
            typer.echo(f"Error: Token verification failed (Status code: {response.status_code})")
            typer.echo(f"Response: {response.text}")
            raise typer.Abort()
        
        user_data = response.json()
        typer.echo(f"Successfully authenticated as {user_data['login']}")
    
    # Save token
    with open(GITHUB_TOKEN_FILE, "w") as f:
        json.dump({"token": token}, f)
    
    # Set permissions to user-only read/write
    os.chmod(GITHUB_TOKEN_FILE, 0o600)
    
    typer.echo(f"GitHub token saved to {GITHUB_TOKEN_FILE}")


def get_github_token():
    """Helper function to retrieve the GitHub token."""
    if not GITHUB_TOKEN_FILE.exists():
        typer.echo("GitHub token not found. Please run 'github-auth' command first.")
        raise typer.Abort()
    
    with open(GITHUB_TOKEN_FILE, "r") as f:
        data = json.load(f)
    
    return data.get("token")


@app.command()
def list_repos(
    username: str = typer.Option(None, "--username", "-u", help="GitHub username (defaults to authenticated user)"),
    limit: int = typer.Option(10, "--limit", "-l", help="Maximum number of repositories to list"),
    sort: str = typer.Option("updated", "--sort", help="Sort repositories by: created, updated, pushed, full_name"),
):
    """
    List GitHub repositories for a user.
    
    This command requires authentication with github-auth first.
    """
    token = get_github_token()
    headers = {"Authorization": f"token {token}"}
    
    # If no username provided, get authenticated user's repos
    if username is None:
        response = requests.get(
            f"https://api.github.com/user/repos?sort={sort}&per_page={limit}",
            headers=headers
        )
    else:
        response = requests.get(
            f"https://api.github.com/users/{username}/repos?sort={sort}&per_page={limit}",
            headers=headers
        )
    
    if response.status_code != 200:
        typer.echo(f"Error: Failed to fetch repositories (Status code: {response.status_code})")
        typer.echo(f"Response: {response.text}")
        raise typer.Abort()
    
    repos = response.json()
    
    if not repos:
        typer.echo("No repositories found.")
        return
    
    # Display repositories in a table format
    typer.echo(f"{'Name':<30} {'Stars':<7} {'Forks':<7} {'Updated':<20}")
    typer.echo("-" * 70)
    
    for repo in repos:
        name = repo["name"]
        stars = repo["stargazers_count"]
        forks = repo["forks_count"]
        updated = repo["updated_at"].split("T")[0]  # Just the date part
        
        typer.echo(f"{name:<30} {stars:<7} {forks:<7} {updated:<20}")


def encrypt_secret(public_key_str: str, secret_value: str) -> str:
    """
    Encrypt a secret using the repository's public key with cryptography library.
    
    Args:
        public_key_str: The public key as a base64 encoded string
        secret_value: The secret value to encrypt
    
    Returns:
        The encrypted value as a base64 encoded string
    """
    # Convert the base64 encoded public key to PEM format
    public_key_bytes = base64.b64decode(public_key_str)
    public_key_pem = b"-----BEGIN PUBLIC KEY-----\n"
    public_key_pem += b"\n".join(base64.b64encode(public_key_bytes[i:i+32]) for i in range(0, len(public_key_bytes), 32))
    public_key_pem += b"\n-----END PUBLIC KEY-----"
    
    # Load the public key
    public_key = load_pem_public_key(public_key_pem)
    
    # Encrypt the secret value
    encrypted = public_key.encrypt(
        secret_value.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )
    
    # Return the encrypted value as a base64 encoded string
    return base64.b64encode(encrypted).decode("utf-8")


@app.command()
def create_repo_secret(
    repo: str = typer.Argument(..., help="Repository name in format 'owner/repo'"),
    name: str = typer.Argument(..., help="Name of the secret"),
    value: str = typer.Option(..., "--value", prompt=True, hide_input=True, help="Value of the secret"),
    environment: str = typer.Option(None, "--environment", "-e", help="Environment name (if setting env-specific secret)"),
):
    """
    Create or update a repository secret (encrypted).
    
    This command requires authentication with github-auth first.
    The token must have 'repo' scope for private repositories or 'public_repo' for public repositories.
    
    Examples:
        - Create a repository-level secret:
          python main.py create-repo-secret octocat/hello-world API_KEY --value mysecretvalue
        
        - Create an environment-specific secret:
          python main.py create-repo-secret octocat/hello-world API_KEY --value mysecretvalue --environment production
    """
    create_repo_value(repo, name, value, RepoValueType.SECRET, environment)


@app.command()
def create_repo_variable(
    repo: str = typer.Argument(..., help="Repository name in format 'owner/repo'"),
    name: str = typer.Argument(..., help="Name of the variable"),
    value: str = typer.Option(..., "--value", prompt=True, help="Value of the variable"),
    environment: str = typer.Option(None, "--environment", "-e", help="Environment name (if setting env-specific variable)"),
):
    """
    Create or update a repository variable (not encrypted).
    
    This command requires authentication with github-auth first.
    The token must have 'repo' scope for private repositories or 'public_repo' for public repositories.
    
    Examples:
        - Create a repository-level variable:
          python main.py create-repo-variable octocat/hello-world NODE_ENV --value production
        
        - Create an environment-specific variable:
          python main.py create-repo-variable octocat/hello-world NODE_ENV --value staging --environment staging
    """
    create_repo_value(repo, name, value, RepoValueType.VARIABLE, environment)


def create_repo_value(
    repo: str,
    name: str,
    value: str,
    value_type: RepoValueType,
    environment: Optional[str] = None,
):
    """
    Helper function to create or update a repository secret or variable.
    
    Args:
        repo: Repository name in format 'owner/repo'
        name: Name of the secret or variable
        value: Value of the secret or variable
        value_type: Type of value (secret or variable)
        environment: Optional environment name
    """
    token = get_github_token()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Validate repository format
    if "/" not in repo:
        typer.echo("Error: Repository must be in format 'owner/repo'")
        raise typer.Abort()
    
    owner, repo_name = repo.split("/", 1)
    
    # Prepare API URLs based on value type
    if value_type == RepoValueType.SECRET:
        # For secrets
        if environment:
            base_url = f"https://api.github.com/repositories/{get_repo_id(owner, repo_name, token)}/environments/{environment}/secrets"
            key_url = f"{base_url}/public-key"
            value_url = f"{base_url}/{name}"
        else:
            base_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/secrets"
            key_url = f"{base_url}/public-key"
            value_url = f"{base_url}/{name}"
            
        # Get public key for encryption
        response = requests.get(key_url, headers=headers)
        
        if response.status_code != 200:
            typer.echo(f"Error: Failed to get public key (Status code: {response.status_code})")
            typer.echo(f"Response: {response.text}")
            raise typer.Abort()
        
        key_data = response.json()
        public_key = key_data["key"]
        key_id = key_data["key_id"]
        
        # Encrypt the secret value
        encrypted_value = encrypt_secret(public_key, value)
        
        # Prepare data for API
        data = {
            "encrypted_value": encrypted_value,
            "key_id": key_id
        }
    else:
        # For variables
        if environment:
            value_url = f"https://api.github.com/repositories/{get_repo_id(owner, repo_name, token)}/environments/{environment}/variables/{name}"
        else:
            value_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/variables/{name}"
            
        # Prepare data for API
        data = {
            "name": name,
            "value": value
        }
    
    # Create or update the secret/variable
    response = requests.put(value_url, headers=headers, json=data)
    
    if response.status_code not in (201, 204):
        typer.echo(f"Error: Failed to create {value_type.value} (Status code: {response.status_code})")
        typer.echo(f"Response: {response.text}")
        raise typer.Abort()
    
    if environment:
        typer.echo(f"{value_type.value.capitalize()} '{name}' created/updated successfully for environment '{environment}' in repository '{repo}'")
    else:
        typer.echo(f"{value_type.value.capitalize()} '{name}' created/updated successfully in repository '{repo}'")


def get_repo_id(owner: str, repo: str, token: str) -> int:
    """Get the repository ID from the owner and repo name."""
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    response = requests.get(f"https://api.github.com/repos/{owner}/{repo}", headers=headers)
    
    if response.status_code != 200:
        typer.echo(f"Error: Failed to get repository information (Status code: {response.status_code})")
        typer.echo(f"Response: {response.text}")
        raise typer.Abort()
    
    return response.json()["id"]


@app.command()
def list_repo_secrets(
    repo: str = typer.Argument(..., help="Repository name in format 'owner/repo'"),
    environment: str = typer.Option(None, "--environment", "-e", help="Environment name (to list env-specific secrets)"),
):
    """
    List secrets for a repository or environment.
    
    This command requires authentication with github-auth first.
    The token must have 'repo' scope for private repositories or 'public_repo' for public repositories.
    
    Note: For security reasons, GitHub API does not return secret values, only names and creation/update dates.
    """
    list_repo_values(repo, RepoValueType.SECRET, environment)


@app.command()
def list_repo_variables(
    repo: str = typer.Argument(..., help="Repository name in format 'owner/repo'"),
    environment: str = typer.Option(None, "--environment", "-e", help="Environment name (to list env-specific variables)"),
):
    """
    List variables for a repository or environment.
    
    This command requires authentication with github-auth first.
    The token must have 'repo' scope for private repositories or 'public_repo' for public repositories.
    """
    list_repo_values(repo, RepoValueType.VARIABLE, environment)


def list_repo_values(
    repo: str,
    value_type: RepoValueType,
    environment: Optional[str] = None,
):
    """
    Helper function to list repository secrets or variables.
    
    Args:
        repo: Repository name in format 'owner/repo'
        value_type: Type of value (secret or variable)
        environment: Optional environment name
    """
    token = get_github_token()
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"
    }
    
    # Validate repository format
    if "/" not in repo:
        typer.echo("Error: Repository must be in format 'owner/repo'")
        raise typer.Abort()
    
    owner, repo_name = repo.split("/", 1)
    
    # Get values
    if environment:
        # Get environment values
        if value_type == RepoValueType.SECRET:
            values_url = f"https://api.github.com/repositories/{get_repo_id(owner, repo_name, token)}/environments/{environment}/secrets"
        else:
            values_url = f"https://api.github.com/repositories/{get_repo_id(owner, repo_name, token)}/environments/{environment}/variables"
    else:
        # Get repository values
        if value_type == RepoValueType.SECRET:
            values_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/secrets"
        else:
            values_url = f"https://api.github.com/repos/{owner}/{repo_name}/actions/variables"
    
    response = requests.get(values_url, headers=headers)
    
    if response.status_code != 200:
        typer.echo(f"Error: Failed to get {value_type.value}s (Status code: {response.status_code})")
        typer.echo(f"Response: {response.text}")
        raise typer.Abort()
    
    # The response structure is different for secrets and variables
    if value_type == RepoValueType.SECRET:
        values = response.json()["secrets"]
    else:
        values = response.json()["variables"]
    
    if not values:
        if environment:
            typer.echo(f"No {value_type.value}s found for environment '{environment}' in repository '{repo}'")
        else:
            typer.echo(f"No {value_type.value}s found for repository '{repo}'")
        return
    
    # Display values in a table format
    if value_type == RepoValueType.SECRET:
        typer.echo(f"{'Name':<30} {'Created':<20} {'Updated':<20}")
        typer.echo("-" * 70)
        
        for value_item in values:
            name = value_item["name"]
            created = value_item.get("created_at", "N/A").split("T")[0] if value_item.get("created_at") else "N/A"
            updated = value_item.get("updated_at", "N/A").split("T")[0] if value_item.get("updated_at") else "N/A"
            
            typer.echo(f"{name:<30} {created:<20} {updated:<20}")
    else:
        typer.echo(f"{'Name':<30} {'Value':<30} {'Created':<20}")
        typer.echo("-" * 80)
        
        for value_item in values:
            name = value_item["name"]
            value = value_item.get("value", "")
            created = value_item.get("created_at", "N/A").split("T")[0] if value_item.get("created_at") else "N/A"
            
            typer.echo(f"{name:<30} {value:<30} {created:<20}")
    
    if environment:
        typer.echo(f"\nFound {len(values)} {value_type.value}s for environment '{environment}' in repository '{repo}'")
    else:
        typer.echo(f"\nFound {len(values)} {value_type.value}s for repository '{repo}'")


@app.command()
def generate_frontend_deploy(
    repo: str = typer.Argument(..., help="Repository name in format 'owner/repo'"),
    output_file: str = typer.Option("deploy-frontend.yml", "--output", "-o", help="Output file name"),
    project_id: str = typer.Option(..., "--project-id", "-p", help="Firebase project ID"),
    frontend_dir: str = typer.Option("./frontend", "--frontend-dir", "-d", help="Path to frontend directory"),
    node_version: str = typer.Option("18", "--node-version", "-n", help="Node.js version to use"),
    branches: str = typer.Option("main,dev", "--branches", "-b", help="Comma-separated list of branches to deploy from"),
    check_secrets: bool = typer.Option(True, "--check-secrets/--no-check-secrets", help="Check if required secrets exist in the repository"),
):
    """
    Generate a GitHub Actions workflow file for deploying a frontend application to Firebase.
    
    This command uses deploy-sample.yml as a template and creates a new workflow file
    specifically for deploying the frontend to Firebase Hosting.
    
    Examples:
        - Generate with default settings:
          python main.py generate-frontend-deploy owner/repo --project-id my-firebase-project
        
        - Customize the output:
          python main.py generate-frontend-deploy owner/repo --output .github/workflows/deploy-frontend.yml --project-id my-project --frontend-dir ./client --node-version 16 --branches main,staging
        
        - Skip checking for secrets:
          python main.py generate-frontend-deploy owner/repo --project-id my-project --no-check-secrets
    """
    # Check if required secrets exist in the repository
    if check_secrets:
        typer.echo("Checking for required secrets and variables in the repository...")
        
        # Validate repository format
        if "/" not in repo:
            typer.echo("Error: Repository must be in format 'owner/repo'")
            raise typer.Abort()
        
        # Get GitHub token
        try:
            token = get_github_token()
            
            # Create a StringIO object to capture the output of list_repo_secrets
            import io
            from contextlib import redirect_stdout
            
            # Check for required secrets
            secrets_output = io.StringIO()
            with redirect_stdout(secrets_output):
                try:
                    # Call list_repo_values directly to avoid the output formatting
                    list_repo_values(repo, RepoValueType.SECRET)
                except typer.Abort:
                    typer.echo("Warning: Failed to get repository secrets.")
                    typer.echo("Skipping secret verification.")
                    check_secrets = False
            
            if check_secrets:
                # Parse the output to get the secret names
                secrets_data = secrets_output.getvalue()
                
                # Extract secret names from the output
                import re
                secret_names = []
                for line in secrets_data.split('\n'):
                    # Skip header and separator lines
                    if line.startswith('Name') or line.startswith('-') or not line.strip():
                        continue
                    # Extract the secret name (first column)
                    match = re.match(r'^(\S+)', line)
                    if match:
                        secret_names.append(match.group(1))
                
                # Check for required secrets
                required_secrets = ["FIREBASE_API_KEY", "FIREBASE_SERVICE_ACCOUNT"]
                missing_secrets = [secret for secret in required_secrets if secret not in secret_names]
                
                if missing_secrets:
                    typer.echo(f"Warning: The following required secrets are missing from the repository: {', '.join(missing_secrets)}")
                    typer.echo("The generated workflow will not work without these secrets.")
                    
                    # Ask if user wants to continue
                    continue_anyway = typer.confirm("Do you want to continue generating the workflow file anyway?")
                    if not continue_anyway:
                        raise typer.Abort()
                else:
                    typer.echo("All required secrets are present in the repository.")
                    
                # Check for required variables
                variables_output = io.StringIO()
                with redirect_stdout(variables_output):
                    try:
                        # Call list_repo_values directly to avoid the output formatting
                        list_repo_values(repo, RepoValueType.VARIABLE)
                    except typer.Abort:
                        typer.echo("Warning: Failed to get repository variables.")
                
                # Parse the output to get the variable names
                variables_data = variables_output.getvalue()
                
                # Extract variable names from the output
                variable_names = []
                for line in variables_data.split('\n'):
                    # Skip header and separator lines
                    if line.startswith('Name') or line.startswith('-') or not line.strip():
                        continue
                    # Extract the variable name (first column)
                    match = re.match(r'^(\S+)', line)
                    if match:
                        variable_names.append(match.group(1))
                
                # Check for required variables
                required_variables = ["FIREBASE_PROJECT_ID"]
                missing_variables = [var for var in required_variables if var not in variable_names]
                
                if missing_variables:
                    typer.echo(f"Warning: The following required variables are missing from the repository: {', '.join(missing_variables)}")
                    typer.echo("The generated workflow will not work correctly without these variables.")
                    
                    # If FIREBASE_PROJECT_ID is missing, suggest setting it
                    if "FIREBASE_PROJECT_ID" in missing_variables:
                        set_project_var = typer.confirm(f"Would you like to set FIREBASE_PROJECT_ID to '{project_id}' now?")
                        if set_project_var:
                            try:
                                # Call create_repo_value directly
                                create_repo_value(repo, "FIREBASE_PROJECT_ID", project_id, RepoValueType.VARIABLE)
                                typer.echo(f"Variable 'FIREBASE_PROJECT_ID' set to '{project_id}'")
                            except typer.Abort:
                                typer.echo("Failed to set FIREBASE_PROJECT_ID variable.")
                                typer.echo("The workflow will be generated, but you must set this variable manually.")
                        else:
                            typer.echo("The workflow will be generated, but you must set FIREBASE_PROJECT_ID manually.")
                            
                            # Ask if user wants to continue
                            continue_anyway = typer.confirm("Do you want to continue generating the workflow file anyway?")
                            if not continue_anyway:
                                raise typer.Abort()
        
        except typer.Abort:
            typer.echo("Warning: GitHub token not found. Skipping secret verification.")
            typer.echo("Please run 'github-auth' command to authenticate with GitHub.")
            check_secrets = False
    
    # Parse branches
    branch_list = [b.strip() for b in branches.split(",")]
    
    # Create the workflow content
    workflow = {
        "name": "Deploy Frontend to Firebase",
        "on": {
            "push": {
                "branches": branch_list
            }
        },
        "env": {
            "FIREBASE_API_KEY": "${{ secrets.FIREBASE_API_KEY }}",
            "PROJECT_ID": "${{ vars.FIREBASE_PROJECT_ID }}"
        },
        "jobs": {
            "deploy_frontend": {
                "permissions": {
                    "contents": "read",
                    "id-token": "write"
                },
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "actions/checkout@v4"
                    },
                    {
                        "name": "Setup Node.js",
                        "uses": "actions/setup-node@v3",
                        "with": {
                            "node-version": node_version
                        }
                    },
                    {
                        "name": "Installing project dependencies",
                        "working-directory": frontend_dir,
                        "run": "npm install"
                    },
                    {
                        "name": "Building the project",
                        "working-directory": frontend_dir,
                        "run": "npm run build"
                    },
                    {
                        "name": "Install Firebase CLI",
                        "run": "npm install -g firebase-tools"
                    },
                    {
                        "name": "Authenticate with Google Cloud",
                        "uses": "google-github-actions/auth@v1",
                        "with": {
                            "credentials_json": "${{ secrets.FIREBASE_SERVICE_ACCOUNT }}"
                        }
                    },
                    {
                        "name": "Deploy to Firebase",
                        "run": f"firebase use $PROJECT_ID && firebase deploy --only hosting"
                    }
                ]
            }
        }
    }
    
    # Convert to YAML
    try:
        from ruamel.yaml import YAML
        from ruamel.yaml.scalarstring import LiteralScalarString
    except ImportError:
        typer.echo("ruamel.yaml is required for this command. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "ruamel.yaml"])
        from ruamel.yaml import YAML
        from ruamel.yaml.scalarstring import LiteralScalarString
    
    # Create output directory if it doesn't exist
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Format multi-line strings as literal blocks
    firebase_deploy_cmd = f"firebase use $PROJECT_ID && firebase deploy --only hosting"
    workflow["jobs"]["deploy_frontend"]["steps"][6]["run"] = LiteralScalarString(firebase_deploy_cmd)
    
    # Configure YAML writer
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 4096  # Set a very large line width to prevent line wrapping
    
    # Write the workflow file
    with open(output_file, "w") as f:
        yaml.dump(workflow, f)
    
    typer.echo(f"Frontend deployment workflow generated at: {output_file}")
    typer.echo(f"Make sure you have the following secrets set in your GitHub repository:")
    typer.echo("  - FIREBASE_API_KEY: Your Firebase API key")
    typer.echo("  - FIREBASE_SERVICE_ACCOUNT: Your Firebase service account credentials JSON")
    typer.echo(f"Required: Set FIREBASE_PROJECT_ID as a repository variable to specify your Firebase project ID")


@app.command()
def generate_backend_deploy(
    repo: str = typer.Argument(..., help="Repository name in format 'owner/repo'"),
    output_file: str = typer.Option("deploy-backend.yml", "--output", "-o", help="Output file name"),
    project_id: str = typer.Option(..., "--project-id", "-p", help="Google Cloud project ID"),
    service_name: str = typer.Option("backend", "--service-name", "-s", help="Cloud Run service name"),
    region: str = typer.Option("asia-southeast1", "--region", "-r", help="Google Cloud region"),
    backend_dir: str = typer.Option("./", "--backend-dir", "-d", help="Path to backend directory"),
    python_version: str = typer.Option("3.12", "--python-version", "-v", help="Python version to use"),
    branches: str = typer.Option("main,dev", "--branches", "-b", help="Comma-separated list of branches to deploy from"),
    check_secrets: bool = typer.Option(True, "--check-secrets/--no-check-secrets", help="Check if required secrets exist in the repository"),
    repomix_file: str = typer.Option(None, "--repomix-file", help="Path to repomix output file to analyze for environment variables"),
):
    """
    Generate a GitHub Actions workflow file for deploying a backend application to Google Cloud Run.
    
    This command creates a workflow file based on the structure found in deploy-sample.yml,
    customized for deploying a Python backend application to Cloud Run.
    
    Examples:
        - Generate with default settings:
          python main.py generate-backend-deploy owner/repo --project-id my-gcp-project
        
        - Customize the output:
          python main.py generate-backend-deploy owner/repo --output .github/workflows/deploy-backend.yml --project-id my-project --service-name api-service --region us-central1 --python-version 3.11 --branches main,staging
        
        - Skip checking for secrets:
          python main.py generate-backend-deploy owner/repo --project-id my-project --no-check-secrets
          
        - Use repomix file to analyze environment variables:
          python main.py generate-backend-deploy owner/repo --project-id my-project --repomix-file repomix-output.txt
    """
    # Initialize variables to store detected environment variables
    detected_env_vars = set()
    detected_secrets = set()
    
    # Check if repomix file is provided and exists
    if repomix_file and os.path.exists(repomix_file):
        typer.echo(f"Analyzing {repomix_file} for environment variables...")
        try:
            # Read the repomix file and extract environment variables
            with open(repomix_file, 'r') as f:
                content = f.read()
                
            # Use regex to find environment variables
            import re
            # Pattern to match os.environ.get("VARIABLE_NAME")
            env_var_pattern = r'os\.environ\.get\("([A-Z_][A-Z0-9_]*)"\)'
            env_vars = re.findall(env_var_pattern, content)
            
            if env_vars:
                # Create categorization mappings for common variable types
                db_password_patterns = ['PASSWORD', 'DB_PASS', 'DATABASE_PASS', 'DBPASS', 'DB_PASSWORD']
                db_user_patterns = ['USER', 'DB_USER', 'DATABASE_USER', 'DBUSER', 'DB_USERNAME']
                db_name_patterns = ['DB', 'DB_NAME', 'DATABASE', 'DATABASE_NAME', 'DBNAME']
                db_connection_patterns = ['CONNECTION', 'CONN', 'DB_CONN', 'SQL_CONNECTION', 'DB_CONNECTION', 'CLOUD_SQL_CONNECTION_NAME']
                api_key_patterns = ['API_KEY', 'APIKEY', 'KEY', 'SECRET_KEY', 'AUTH_KEY']
                firebase_patterns = ['FIREBASE', 'FIREBASE_KEY', 'FIREBASE_SECRET']
                
                # Initialize variable categories
                db_password_vars = []
                db_user_vars = []
                db_name_vars = []
                db_connection_vars = []
                api_key_vars = []
                firebase_vars = []
                other_vars = []
                
                # Categorize variables
                unique_vars = sorted(set(env_vars))
                typer.echo(f"Found {len(unique_vars)} environment variables in the codebase:")
                
                for var in unique_vars:
                    typer.echo(f"  - {var}")
                    
                    # Check if variable matches any category
                    var_upper = var.upper()
                    
                    # Database password variables
                    if any(pattern in var_upper for pattern in db_password_patterns):
                        db_password_vars.append(var)
                        detected_secrets.add(var)
                    
                    # Database user variables
                    elif any(pattern in var_upper for pattern in db_user_patterns):
                        db_user_vars.append(var)
                        detected_env_vars.add(var)
                    
                    # Database name variables
                    elif any(pattern in var_upper for pattern in db_name_patterns):
                        db_name_vars.append(var)
                        detected_env_vars.add(var)
                    
                    # Database connection variables
                    elif any(pattern in var_upper for pattern in db_connection_patterns):
                        db_connection_vars.append(var)
                        detected_env_vars.add(var)
                    
                    # API key variables
                    elif any(pattern in var_upper for pattern in api_key_patterns):
                        api_key_vars.append(var)
                        detected_secrets.add(var)
                    
                    # Firebase variables
                    elif any(pattern in var_upper for pattern in firebase_patterns):
                        firebase_vars.append(var)
                        detected_secrets.add(var)
                    
                    # Other variables that are likely secrets
                    elif any(secret_word in var_upper for secret_word in ['SECRET', 'PASSWORD', 'PASS', 'KEY', 'TOKEN', 'PRIVATE']):
                        detected_secrets.add(var)
                        other_vars.append(var)
                    
                    # All other variables
                    else:
                        detected_env_vars.add(var)
                        other_vars.append(var)
                
                # Store the categorized variables for later use
                var_categories = {
                    'db_password': db_password_vars[0] if db_password_vars else None,
                    'db_user': db_user_vars[0] if db_user_vars else None,
                    'db_name': db_name_vars[0] if db_name_vars else None,
                    'db_connection': db_connection_vars[0] if db_connection_vars else None,
                    'firebase_key': next((var for var in firebase_vars if 'KEY' in var.upper()), 
                                        firebase_vars[0] if firebase_vars else None),
                    'api_keys': api_key_vars,
                    'other_secrets': [var for var in detected_secrets if var not in db_password_vars + firebase_vars + api_key_vars],
                    'other_vars': [var for var in detected_env_vars if var not in db_user_vars + db_name_vars + db_connection_vars]
                }
                
                # Print categorization summary
                typer.echo("\nVariable categorization:")
                if var_categories['db_password']:
                    typer.echo(f"  Database password: {var_categories['db_password']}")
                if var_categories['db_user']:
                    typer.echo(f"  Database user: {var_categories['db_user']}")
                if var_categories['db_name']:
                    typer.echo(f"  Database name: {var_categories['db_name']}")
                if var_categories['db_connection']:
                    typer.echo(f"  Database connection: {var_categories['db_connection']}")
                if var_categories['firebase_key']:
                    typer.echo(f"  Firebase key: {var_categories['firebase_key']}")
                if var_categories['api_keys']:
                    typer.echo(f"  API keys: {', '.join(var_categories['api_keys'])}")
                
        except Exception as e:
            typer.echo(f"Error analyzing repomix file: {e}")
            typer.echo("Continuing with default environment variables...")
            # Initialize empty categories if analysis failed
            var_categories = {
                'db_password': None,
                'db_user': None,
                'db_name': None,
                'db_connection': None,
                'firebase_key': None,
                'api_keys': [],
                'other_secrets': [],
                'other_vars': []
            }
    else:
        # Initialize empty categories if no repomix file
        var_categories = {
            'db_password': None,
            'db_user': None,
            'db_name': None,
            'db_connection': None,
            'firebase_key': None,
            'api_keys': [],
            'other_secrets': [],
            'other_vars': []
        }
    
    # Check if required secrets exist in the repository
    if check_secrets:
        typer.echo("Checking for required secrets and variables in the repository...")
        
        # Validate repository format
        if "/" not in repo:
            typer.echo("Error: Repository must be in format 'owner/repo'")
            raise typer.Abort()
        
        # Get GitHub token
        try:
            token = get_github_token()
            
            # Create a StringIO object to capture the output of list_repo_secrets
            import io
            from contextlib import redirect_stdout
            
            # Check for required secrets
            secrets_output = io.StringIO()
            with redirect_stdout(secrets_output):
                try:
                    # Call list_repo_values directly to avoid the output formatting
                    list_repo_values(repo, RepoValueType.SECRET)
                except typer.Abort:
                    typer.echo("Warning: Failed to get repository secrets.")
                    typer.echo("Skipping secret verification.")
                    check_secrets = False
            
            if check_secrets:
                # Parse the output to get the secret names
                secrets_data = secrets_output.getvalue()
                
                # Extract secret names from the output
                import re
                secret_names = []
                for line in secrets_data.split('\n'):
                    # Skip header and separator lines
                    if line.startswith('Name') or line.startswith('-') or not line.strip():
                        continue
                    # Extract the secret name (first column)
                    match = re.match(r'^(\S+)', line)
                    if match:
                        secret_names.append(match.group(1))
                
                # Determine required secrets based on detected environment variables
                required_secrets = ["CLOUDRUN_SERVICE_ACCOUNT"]
                if var_categories['db_password']:
                    required_secrets.append(var_categories['db_password'])
                if var_categories['firebase_key']:
                    required_secrets.append(var_categories['firebase_key'])
                for api_key in var_categories['api_keys']:
                    required_secrets.append(api_key)
                
                missing_secrets = [secret for secret in required_secrets if secret not in secret_names]
                
                if missing_secrets:
                    typer.echo(f"Warning: The following required secrets are missing from the repository: {', '.join(missing_secrets)}")
                    typer.echo("The generated workflow will not work without these secrets.")
                    
                    # Ask if user wants to continue
                    continue_anyway = typer.confirm("Do you want to continue generating the workflow file anyway?")
                    if not continue_anyway:
                        raise typer.Abort()
                else:
                    typer.echo("All required secrets are present in the repository.")
                    
                # Check for required variables
                variables_output = io.StringIO()
                with redirect_stdout(variables_output):
                    try:
                        # Call list_repo_values directly to avoid the output formatting
                        list_repo_values(repo, RepoValueType.VARIABLE)
                    except typer.Abort:
                        typer.echo("Warning: Failed to get repository variables.")
                
                # Parse the output to get the variable names
                variables_data = variables_output.getvalue()
                
                # Extract variable names from the output
                variable_names = []
                for line in variables_data.split('\n'):
                    # Skip header and separator lines
                    if line.startswith('Name') or line.startswith('-') or not line.strip():
                        continue
                    # Extract the variable name (first column)
                    match = re.match(r'^(\S+)', line)
                    if match:
                        variable_names.append(match.group(1))
                
                # Determine required variables based on detected environment variables
                required_variables = []
                if var_categories['db_connection']:
                    required_variables.append(var_categories['db_connection'])
                if var_categories['db_user']:
                    required_variables.append(var_categories['db_user'])
                if var_categories['db_name']:
                    required_variables.append(var_categories['db_name'])
                
                # If no variables were detected, use defaults
                if not required_variables:
                    required_variables = ["CLOUD_SQL_CONNECTION_NAME", "POSTGRES_USER", "POSTGRES_DB"]
                
                missing_variables = [var for var in required_variables if var not in variable_names]
                
                if missing_variables:
                    typer.echo(f"Warning: The following required variables are missing from the repository: {', '.join(missing_variables)}")
                    typer.echo("The generated workflow will not work correctly without these variables.")
                    
                    # Ask if user wants to continue
                    continue_anyway = typer.confirm("Do you want to continue generating the workflow file anyway?")
                    if not continue_anyway:
                        raise typer.Abort()
        
        except typer.Abort:
            typer.echo("Warning: GitHub token not found. Skipping secret verification.")
            typer.echo("Please run 'github-auth' command to authenticate with GitHub.")
            check_secrets = False
    
    # Parse branches
    branch_list = [b.strip() for b in branches.split(",")]
    
    # Create the workflow content
    workflow = {
        "name": f"Deploy {service_name} to Cloud Run",
        "on": {
            "push": {
                "branches": branch_list
            }
        },
        "env": {
            "PROJECT_ID": project_id,
            "GAR_LOCATION": region,
            "REPOSITORY": "cloud-run-source-deploy",
            "SERVICE": service_name,
            "REGION": region
        },
        "jobs": {
            "build_and_deploy": {
                "permissions": {
                    "contents": "read",
                    "id-token": "write"
                },
                "runs-on": "ubuntu-latest",
                "steps": [
                    {
                        "uses": "actions/checkout@v4"
                    },
                    {
                        "name": "Google Auth",
                        "id": "auth",
                        "uses": "google-github-actions/auth@v2",
                        "with": {
                            "credentials_json": "${{ secrets.CLOUDRUN_SERVICE_ACCOUNT }}",
                            "token_format": "access_token"
                        }
                    },
                    {
                        "name": "Docker Auth",
                        "id": "docker-auth",
                        "uses": "docker/login-action@v1",
                        "with": {
                            "username": "oauth2accesstoken",
                            "password": "${{ steps.auth.outputs.access_token }}",
                            "registry": "${{ env.GAR_LOCATION }}-docker.pkg.dev"
                        }
                    },
                    {
                        "name": "Build and Push Container",
                        "run": f"docker build -t \"${{{{ env.GAR_LOCATION }}}}-docker.pkg.dev/${{{{ env.PROJECT_ID }}}}/${{{{ env.REPOSITORY }}}}/${{{{ env.SERVICE }}}}:${{{{ github.sha }}}}\" {backend_dir}\ndocker push \"${{{{ env.GAR_LOCATION }}}}-docker.pkg.dev/${{{{ env.PROJECT_ID }}}}/${{{{ env.REPOSITORY }}}}/${{{{ env.SERVICE }}}}:${{{{ github.sha }}}}\""
                    },
                    {
                        "name": "Deploy to Cloud Run",
                        "id": "deploy",
                        "uses": "google-github-actions/deploy-cloudrun@v2",
                        "with": {
                            "service": "${{ env.SERVICE }}",
                            "region": "${{ env.REGION }}",
                            "image": "${{ env.GAR_LOCATION }}-docker.pkg.dev/${{ env.PROJECT_ID }}/${{ env.REPOSITORY }}/${{ env.SERVICE }}:${{ github.sha }}",
                            "flags": f"--allow-unauthenticated{' --set-cloudsql-instances=${{ vars.' + var_categories['db_connection'] + ' }}' if var_categories['db_connection'] else ''}",
                        }
                    },
                    {
                        "name": "Installing Python",
                        "uses": "actions/setup-python@v4",
                        "with": {
                            "python-version": python_version
                        }
                    },
                    {
                        "name": "Installing Python Dependencies",
                        "run": f"pip install -r {backend_dir}/requirements.txt"
                    },
                    {
                        "name": "Run Python Tests",
                        "run": f"python -m pytest {backend_dir}/tests/"
                    }
                ]
            }
        }
    }
    
    # Add Firebase API Key to env if detected
    if var_categories['firebase_key']:
        workflow["env"]["FIREBASE_API_KEY"] = f"${{{{ secrets.{var_categories['firebase_key']} }}}}"
    
    # Build environment variables string based on detected variables
    env_vars_list = []
    
    # Add detected environment variables
    if var_categories['db_user']:
        env_vars_list.append(f"{var_categories['db_user']}='${{{{ vars.{var_categories['db_user']} }}}}'")
    
    if var_categories['db_password']:
        env_vars_list.append(f"{var_categories['db_password']}='${{{{ secrets.{var_categories['db_password']} }}}}'")
    
    if var_categories['db_name']:
        env_vars_list.append(f"{var_categories['db_name']}='${{{{ vars.{var_categories['db_name']} }}}}'")
    
    if var_categories['firebase_key']:
        env_vars_list.append(f"{var_categories['firebase_key']}='${{{{ secrets.{var_categories['firebase_key']} }}}}'")
    
    if var_categories['db_connection']:
        env_vars_list.append(f"{var_categories['db_connection']}='${{{{ vars.{var_categories['db_connection']} }}}}'")
    
    # Add API keys
    for api_key in var_categories['api_keys']:
        if api_key != var_categories['firebase_key']:  # Avoid duplication
            env_vars_list.append(f"{api_key}='${{{{ secrets.{api_key} }}}}'")
    
    # Add other secrets
    for secret in var_categories['other_secrets']:
        env_vars_list.append(f"{secret}='${{{{ secrets.{secret} }}}}'")
    
    # Add other variables
    for var in var_categories['other_vars']:
        if var not in ["PORT", "POSTGRES_PORT"]:  # Skip common variables that don't need explanation
            env_vars_list.append(f"{var}='${{{{ vars.{var} }}}}'")
    
    # Special case for PORT which is commonly needed
    if "PORT" in detected_env_vars:
        env_vars_list.append("PORT='8080'")
    
    # If no environment variables were detected, use defaults
    if not env_vars_list:
        env_vars_list = [
            "POSTGRES_USER='${{ vars.POSTGRES_USER }}'",
            "POSTGRES_PASSWORD='${{ secrets.POSTGRES_PASSWORD }}'",
            "POSTGRES_DB='${{ vars.POSTGRES_DB }}'",
            "FIREBASE_API_KEY='${{ secrets.FIREBASE_API_KEY }}'",
            "CLOUD_SQL_CONNECTION_NAME='${{ vars.CLOUD_SQL_CONNECTION_NAME }}'"
        ]
    
    # Join environment variables with newlines
    env_vars_str = "\n".join(env_vars_list)
    
    # Add environment variables to the deploy step
    workflow["jobs"]["build_and_deploy"]["steps"][4]["with"]["env_vars"] = env_vars_str
    
    # Convert to YAML
    try:
        from ruamel.yaml import YAML
        from ruamel.yaml.scalarstring import LiteralScalarString
    except ImportError:
        typer.echo("ruamel.yaml is required for this command. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "ruamel.yaml"])
        from ruamel.yaml import YAML
        from ruamel.yaml.scalarstring import LiteralScalarString
    
    # Create output directory if it doesn't exist
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Format multi-line strings as literal blocks
    build_push_cmd = f"docker build -t \"${{{{ env.GAR_LOCATION }}}}-docker.pkg.dev/${{{{ env.PROJECT_ID }}}}/${{{{ env.REPOSITORY }}}}/${{{{ env.SERVICE }}}}:${{{{ github.sha }}}}\" {backend_dir}\ndocker push \"${{{{ env.GAR_LOCATION }}}}-docker.pkg.dev/${{{{ env.PROJECT_ID }}}}/${{{{ env.REPOSITORY }}}}/${{{{ env.SERVICE }}}}:${{{{ github.sha }}}}\""
    
    # Replace the strings with LiteralScalarString objects
    workflow["jobs"]["build_and_deploy"]["steps"][3]["run"] = LiteralScalarString(build_push_cmd)
    workflow["jobs"]["build_and_deploy"]["steps"][4]["with"]["env_vars"] = LiteralScalarString(env_vars_str)
    
    # Configure YAML writer
    yaml = YAML()
    yaml.preserve_quotes = True
    yaml.indent(mapping=2, sequence=4, offset=2)
    yaml.width = 4096  # Set a very large line width to prevent line wrapping
    
    # Write the workflow file
    with open(output_file, "w") as f:
        yaml.dump(workflow, f)
    
    typer.echo(f"Backend deployment workflow generated at: {output_file}")
    typer.echo(f"Make sure you have the following secrets set in your GitHub repository:")
    typer.echo("  - CLOUDRUN_SERVICE_ACCOUNT: Your Google Cloud service account credentials JSON")
    
    # Display detected secrets
    if var_categories['db_password']:
        typer.echo(f"  - {var_categories['db_password']}: Your database password")
    
    if var_categories['firebase_key']:
        typer.echo(f"  - {var_categories['firebase_key']}: Your Firebase API key")
    
    for api_key in var_categories['api_keys']:
        if api_key != var_categories['firebase_key']:  # Avoid duplication
            typer.echo(f"  - {api_key}: Your API key")
    
    for secret in var_categories['other_secrets']:
        typer.echo(f"  - {secret}: Your {secret.replace('_', ' ').title()}")
    
    typer.echo(f"\nMake sure you have the following variables set in your GitHub repository:")
    
    # Display detected variables
    if var_categories['db_connection']:
        typer.echo(f"  - {var_categories['db_connection']}: Your database connection string")
    
    if var_categories['db_user']:
        typer.echo(f"  - {var_categories['db_user']}: Your database username")
    
    if var_categories['db_name']:
        typer.echo(f"  - {var_categories['db_name']}: Your database name")
    
    for var in var_categories['other_vars']:
        if var not in ["PORT", "POSTGRES_PORT"]:  # Skip common variables that don't need explanation
            typer.echo(f"  - {var}: Your {var.replace('_', ' ').title()}")


@app.command()
def run_repomix(
    target_folder: str = typer.Argument(..., help="Target folder to run repomix against"),
):
    """
    Execute repomix targeting a specific folder.
    
    This command requires the repomix npm package to be installed globally.
    If it's not installed, the command will offer to install it.
    
    Examples:
        - Run repomix in the current directory:
          python main.py run-repomix .
        
        - Run repomix in a specific folder:
          python main.py run-repomix ./my-project
    """
    # Check if repomix is installed
    if not check_repomix_installed():
        typer.echo("Repomix is required for this command. Please install it and try again.")
        raise typer.Abort()
    
    # Get the absolute path of the target folder
    target_path = os.path.abspath(target_folder)
    
    # Check if the directory exists
    if not os.path.isdir(target_path):
        typer.echo(f"Error: Target folder '{target_folder}' does not exist or is not a directory.")
        raise typer.Abort()
    
    # Prepare the command with the target path as an argument
    cmd = ["npx", "repomix", target_path]
    
    typer.echo(f"Running repomix against {target_path}...")
    
    try:
        # Execute the command
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            universal_newlines=True
        )
        
        # Stream the output in real-time
        for line in iter(process.stdout.readline, ""):
            if not line:
                break
            typer.echo(line.strip())
        
        # Get the return code
        return_code = process.wait()
        
        # Collect stderr
        stderr_lines = []
        for line in iter(process.stderr.readline, ""):
            if not line:
                break
            stderr_lines.append(line.strip())
        
        # Check for errors
        if return_code != 0:
            typer.echo(f"Error executing repomix command (exit code {return_code}):")
            for line in stderr_lines:
                typer.echo(line)
            raise typer.Abort()
        
        typer.echo(f"Repomix completed successfully.")
        
    except subprocess.CalledProcessError as e:
        typer.echo(f"Error executing repomix command: {e}")
        raise typer.Abort()
    except Exception as e:
        typer.echo(f"An unexpected error occurred: {e}")
        raise typer.Abort()


def main():
    """Main entry point for the application."""
    # Check if repomix is installed
    check_repomix_installed()
    
    # Run the Typer app
    app()


if __name__ == "__main__":
    main()
