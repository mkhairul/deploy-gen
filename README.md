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

### Building a Standalone Binary

You can build a standalone executable that includes all dependencies:

#### Prerequisites

1. Make sure you have activated your virtual environment:
   - Windows: `.venv\Scripts\activate`
   - Unix/MacOS: `source .venv/bin/activate`

2. Ensure all dependencies are installed:
   ```bash
   pip install -r requirements.txt
   ```

#### Building the Binary

##### Windows
```bash
# Run the build script
build.bat
```

##### Unix/Linux/macOS
```bash
# Make the build script executable
chmod +x build.sh

# Run the build script
./build.sh
```

The build process will create two types of executables:

1. **Directory-based distribution** in `dist/deploy-gen/`:
   - Contains the main executable and supporting files
   - Recommended for local use
   - More efficient as it loads libraries only when needed

2. **Single-file executable** at `dist/deploy-gen-onefile`:
   - Everything bundled into a single file
   - Easier to distribute to others
   - Slightly slower to start as it needs to extract files to a temporary location

##### Notes on Building

- The build scripts will check if you're in a virtual environment and use the Python interpreter from that environment
- If no virtual environment is active, the scripts will warn you and ask if you want to continue
- All Python dependencies will be included in the binary
- Node.js and npm are still required separately if you need features that use the repomix package
- If you encounter any issues with the build, check the error messages for guidance

### Dependencies

The application has the following dependencies:

#### Python Dependencies
- **typer**: For building the CLI interface
- **requests**: For making HTTP requests to the GitHub API
- **cryptography**: For encrypting secrets (compatible with Python 3.12+)
- **pyyaml**: For generating YAML configuration files

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

#### Generate Frontend Deployment Workflow

Generate a GitHub Actions workflow file for deploying a frontend application to Firebase:

```bash
python main.py generate-frontend-deploy owner/repo --project-id my-firebase-project
```

With options:

```bash
# Customize the output file path
python main.py generate-frontend-deploy owner/repo --output .github/workflows/deploy-frontend.yml --project-id my-project

# Specify a different frontend directory
python main.py generate-frontend-deploy owner/repo --project-id my-project --frontend-dir ./client

# Set a specific Node.js version
python main.py generate-frontend-deploy owner/repo --project-id my-project --node-version 16

# Deploy from specific branches
python main.py generate-frontend-deploy owner/repo --project-id my-project --branches main,staging,production

# Skip checking for required secrets
python main.py generate-frontend-deploy owner/repo --project-id my-project --no-check-secrets
```

This command generates a GitHub Actions workflow file that:
1. Triggers on pushes to specified branches
2. Sets up the specified Node.js version
3. Installs dependencies and builds the frontend
4. Deploys the built frontend to Firebase Hosting

By default, the command:
- Checks if the required secrets exist in your GitHub repository and warns you if any are missing
- Checks if the required FIREBASE_PROJECT_ID variable exists
- Offers to create the FIREBASE_PROJECT_ID variable if it doesn't exist
- Uses the FIREBASE_PROJECT_ID variable in the workflow

You can disable these checks with the `--no-check-secrets` flag.

**Required GitHub Secrets:**
- `FIREBASE_API_KEY`: Your Firebase API key
- `FIREBASE_SERVICE_ACCOUNT`: Your Firebase service account credentials JSON

**Required GitHub Variables:**
- `FIREBASE_PROJECT_ID`: Your Firebase project ID

#### Run Repomix Commands

Execute repomix targeting a specific folder:

```bash
# Run repomix against the current directory
python main.py run-repomix .

# Run repomix against a specific folder
python main.py run-repomix ./my-project
```

This command:
1. Checks if the repomix npm package is installed globally
2. Offers to install it if it's not found
3. Executes `npx repomix /path/to/folder` with the target folder as an argument
4. Streams the command output in real-time

The command requires:
- Node.js and npm to be installed
- Internet connection (for npx to fetch repomix if needed)

#### Generate Backend Deployment Workflow

Generate a GitHub Actions workflow file for deploying a backend application to Google Cloud Run:

```bash
# Generate with default settings
python main.py generate-backend-deploy owner/repo --project-id my-gcp-project

# Customize the output
python main.py generate-backend-deploy owner/repo --output .github/workflows/deploy-backend.yml --project-id my-project --service-name api-service --region us-central1 --python-version 3.11 --branches main,staging

# Skip checking for secrets
python main.py generate-backend-deploy owner/repo --project-id my-project --no-check-secrets
```

This command generates a GitHub Actions workflow file that:
1. Triggers on pushes to specified branches
2. Authenticates with Google Cloud
3. Builds and pushes a Docker container to Google Artifact Registry
4. Deploys the container to Cloud Run
5. Sets up Python and runs tests

By default, the command:
- Checks if the required secrets exist in your GitHub repository and warns you if any are missing
- Checks if the required variables exist in your GitHub repository
- Uses the specified project ID and region in the workflow

You can disable these checks with the `--no-check-secrets` flag.

**Required GitHub Secrets:**
- `CLOUDRUN_SERVICE_ACCOUNT`: Your Google Cloud service account credentials JSON
- `FIREBASE_API_KEY`: Your Firebase API key
- `POSTGRES_PASSWORD`: Your PostgreSQL database password

**Required GitHub Variables:**
- `CLOUD_SQL_CONNECTION_NAME`: Your Cloud SQL connection name
- `POSTGRES_USER`: Your PostgreSQL database username
- `POSTGRES_DB`: Your PostgreSQL database name
