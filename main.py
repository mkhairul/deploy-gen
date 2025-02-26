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

app = typer.Typer(help="A simple CLI application using Typer")

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
        import yaml
    except ImportError:
        typer.echo("PyYAML is required for this command. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "PyYAML"])
        import yaml
    
    # Create output directory if it doesn't exist
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Write the workflow file
    with open(output_file, "w") as f:
        yaml.dump(workflow, f, default_flow_style=False, sort_keys=False)
    
    typer.echo(f"Frontend deployment workflow generated at: {output_file}")
    typer.echo(f"Make sure you have the following secrets set in your GitHub repository:")
    typer.echo("  - FIREBASE_API_KEY: Your Firebase API key")
    typer.echo("  - FIREBASE_SERVICE_ACCOUNT: Your Firebase service account credentials JSON")
    typer.echo(f"Required: Set FIREBASE_PROJECT_ID as a repository variable to specify your Firebase project ID")


def main():
    """Main entry point for the application."""
    # Check if repomix is installed
    check_repomix_installed()
    
    # Run the Typer app
    app()


if __name__ == "__main__":
    main()
