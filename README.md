# deploy-gen
Deployment Generator for GAIA

## Typer CLI Application

This is a simple command-line application built with Typer.

### Installation

1. Clone this repository
2. Create a virtual environment: `python -m venv .venv`
3. Activate the virtual environment:
   - Windows: `.venv\Scripts\activate`
   - Unix/MacOS: `source .venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Install Node.js dependencies (if needed):
   - Make sure Node.js and npm are installed
   - Install repomix globally: `npm install -g repomix`

### Dependencies

The application has the following dependencies:

#### Python Dependencies
- **typer**: For building the CLI interface
- **requests**: For making HTTP requests to the GitHub API
- **pynacl**: For encrypting secrets

#### Node.js Dependencies
- **repomix** (npm package): For additional repository management features

When you run the application for the first time, it will check if the repomix npm package is installed globally and offer to install it if it's missing.

### Usage

The application provides several commands:

#### Hello Command

Greet a user:

```bash
python main.py hello John
```

With options:

```bash
python main.py hello John --count 3 --formal
```

#### Info Command

Display information about the application:

```bash
python main.py info
python main.py info --verbose
```

#### Export Command

Export data to a file:

```bash
python main.py export output.txt
python main.py export output.json --format json
python main.py export output.txt --format table --quiet
```

#### GitHub Authentication

Authenticate with GitHub using a personal access token:

```bash
python main.py github-auth
```

With options:

```bash
python main.py github-auth --token YOUR_TOKEN --force
python main.py github-auth --no-verify
```

The token will be stored securely in your user directory (`~/.deploy-gen/github_token.json`) for future use.

#### List GitHub Repositories

List repositories for a user (requires authentication first):

```bash
python main.py list-repos
python main.py list-repos --username octocat --limit 20 --sort full_name
```

#### Repository Secrets and Variables

GitHub offers two types of repository values:
- **Secrets**: Encrypted values that are masked in logs (for sensitive data)
- **Variables**: Plain text values that are visible in logs (for non-sensitive data)

##### Create Repository Secrets

Create or update a secret for a GitHub repository:

```bash
python main.py create-repo-secret owner/repo SECRET_NAME
```

With options:

```bash
# Specify the value directly (not recommended for sensitive data)
python main.py create-repo-secret owner/repo API_KEY --value mysecretvalue

# Create an environment-specific secret
python main.py create-repo-secret owner/repo DATABASE_URL --environment production
```

##### Create Repository Variables

Create or update a variable for a GitHub repository:

```bash
python main.py create-repo-variable owner/repo VARIABLE_NAME
```

With options:

```bash
# Specify the value directly
python main.py create-repo-variable owner/repo NODE_ENV --value production

# Create an environment-specific variable
python main.py create-repo-variable owner/repo DEPLOY_TARGET --value staging --environment staging
```

##### List Repository Secrets

List secrets for a repository or environment:

```bash
python main.py list-repo-secrets owner/repo
python main.py list-repo-secrets owner/repo --environment production
```

Note: For security reasons, GitHub API does not return secret values, only names and creation/update dates.

##### List Repository Variables

List variables for a repository or environment:

```bash
python main.py list-repo-variables owner/repo
python main.py list-repo-variables owner/repo --environment staging
```

Unlike secrets, variable values are visible in the output.

### Available Formats

- `text` (default): Plain text format
- `json`: JSON format
- `table`: Simple ASCII table format

### Help

For more information, use the `--help` option:

```bash
python main.py --help
python main.py hello --help
python main.py github-auth --help
python main.py create-repo-secret --help
python main.py create-repo-variable --help
```
