import typer
from typing import Optional, Literal
from enum import Enum
import os
import requests
import json
from pathlib import Path
import base64
from nacl import encoding, public
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


def encrypt_secret(public_key: str, secret_value: str) -> str:
    """Encrypt a secret using the repository's public key."""
    public_key = public.PublicKey(public_key.encode("utf-8"), encoding.Base64Encoder())
    sealed_box = public.SealedBox(public_key)
    encrypted = sealed_box.encrypt(secret_value.encode("utf-8"))
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


def main():
    """Main entry point for the application."""
    # Check if repomix is installed
    check_repomix_installed()
    
    # Run the Typer app
    app()


if __name__ == "__main__":
    main()
