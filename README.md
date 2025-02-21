# Vault JWT GitLab Demo

This repository contains a Python script that demonstrates how to authenticate to HashiCorp Vault using the JWT authentication method with a GitLab id token. The script then performs various secret operations—reading, deleting, and writing secrets—using Vault's KV v2 secrets engine.

## Overview

- **Authentication**: Uses a GitLab-provided JWT (`id_token`) to obtain a Vault token via Vault's JWT auth endpoint.
- **Secret Operations**:  
  - Reads a secret from a specified path twice.
  - Deletes the secret and verifies the deletion.
  - Writes new secret values (with a timestamp) to two secret paths.
- **Error Handling**: Each Vault API operation is wrapped in a try/except block to catch and print errors.

## Prerequisites

- **Python 3.x**: Ensure you have Python 3 installed.
- **Requests Library**: Install with:

```
  pip install requests
```

## HashiCorp Vault: An accessible Vault instance configured with the JWT auth method.
- GitLab CI/CD: Set up your GitLab CI/CD pipeline with the Vault id token.

#### Configuration

The following variables are hard-coded in the script for demonstration purposes. In future iterations, these values can be passed as environment variables through your CI/CD system.


```
VAULT_ADDR = "https://services.vault.com"
TENANT_NAMESPACE = "some-random-namespace"
VAULT_AUTH_PATH = "/auth/jwt/login"    # Full path: /v1/auth/jwt/login
VAULT_AUTH_ROLE = "gitlab-role"
VAULT_MOUNT_POINT = "jwt"              # For best practices (not explicitly used here)

SECRET_PATH_1 = "/kv/data/some-secretA"
SECRET_PATH_2 = "/kv/data/some-secretB"
The GitLab provided JWT token (id_token) is also hard-coded for demo purposes:
```

```
id_token = "your-id-token-here"  # Replace with the actual id_token from GitLab
```

## How It Works

Authentication
The script sends a POST request to:


```
{VAULT_ADDR}/v1{VAULT_AUTH_PATH}/login
with headers:

Content-Type: application/json
X-Vault-Namespace: {TENANT_NAMESPACE}
and a JSON payload:
```

Json Body 

```
{
  "jwt": "your-id-token-here",
  "role": "gitlab-role"
}
```

The response is parsed to extract the Vault token.

### Secret Operations

- Read Secret: Reads the secret at SECRET_PATH_1 (KV v2 structure: data is nested under data.data).
- Delete Secret: Deletes the secret at SECRET_PATH_1 and verifies by attempting to read it again.
- Write Secret: Writes new secret values to both SECRET_PATH_1 and SECRET_PATH_2 using a payload under the "data" key, appending a timestamp to differentiate the values.


# Cleanup
- The script resets sensitive variables after completion.


Clone the Repository

```
git clone https://github.com/yourusername/vault-jwt-gitlab-demo.git
cd vault-jwt-gitlab-demo
Install Dependencies
```

```
pip install requests
```


## Configure the Script

- Update the Vault address, tenant namespace, and authentication details in the Python script.
- Replace the placeholder id_token with your GitLab id token.
- Run the Script


```
python3 vault_jwt_gitlab_demo.py
```


## GitLab CI/CD Integration
Below is an example snippet for a GitLab CI/CD job that sets the Vault id token and runs the script:


```
job_with_secrets:
  script:
    - python3 vault_jwt_gitlab_demo.py
  id_tokens:
    VAULT_ID_TOKEN:
      aud: https://vault.example.com
```

- In this setup, the GitLab CI file will provide the VAULT_ID_TOKEN as the JWT token (id_token) required for authentication.

## References

- HashiCorp Vault JWT Authentication Documentation
- HashiCorp Vault KV v2 Secrets Engine
- GitLab CI/CD Secrets with HashiCorp Vault
- HashiCorp HCP Vault Secrets Retrieval with GitLab

  
License
This project is licensed under the MIT License. See the LICENSE file for details.
