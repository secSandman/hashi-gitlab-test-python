import requests
import time
import json

# Variables (to be externalized later)
VAULT_ADDR = "https://services.vault.com"
TENANT_NAMESPACE = "some-random-namespace"
VAULT_AUTH_PATH = "/auth/jwt/login"    # Full auth path is /v1/auth/jwt/login
VAULT_AUTH_ROLE = "gitlab-role"
VAULT_MOUNT_POINT = "jwt"              # Not used explicitly here, but part of best practices

# Secret paths for KV v2 secrets
SECRET_PATH_1 = "/kv/data/some-secretA"
SECRET_PATH_2 = "/kv/data/some-secretB"

# GitLab provided id_token; in a real CI/CD run, this would be provided as an environment variable.
id_token = "your-id-token-here"  # Replace with the actual id_token from GitLab

def authenticate_to_vault():
    auth_url = f"{VAULT_ADDR}/v1{VAULT_AUTH_PATH}"
    headers = {
        "Content-Type": "application/json",
        "X-Vault-Namespace": TENANT_NAMESPACE
    }
    data = {
        "jwt": id_token,
        "role": VAULT_AUTH_ROLE
    }
    try:
        response = requests.post(auth_url, headers=headers, json=data)
        response.raise_for_status()
        result = response.json()
        vault_token = result.get("auth", {}).get("client_token")
        if not vault_token:
            print("Error: Vault token not found in authentication response.")
            return None
        print("Authentication successful. Vault token obtained.")
        return vault_token
    except Exception as e:
        print(f"Vault authentication error: {e}")
        return None

def read_secret(vault_token, secret_path):
    url = f"{VAULT_ADDR}/v1{secret_path}"
    headers = {
        "X-Vault-Token": vault_token,
        "X-Vault-Namespace": TENANT_NAMESPACE
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        # For KV v2, the secret value is nested in data.data
        secret_value = response.json().get("data", {}).get("data")
        print(f"Successfully read secret from {secret_path}: {secret_value}")
    except Exception as e:
        print(f"Error reading secret from {secret_path}: {e}")

def delete_secret(vault_token, secret_path):
    url = f"{VAULT_ADDR}/v1{secret_path}"
    headers = {
        "X-Vault-Token": vault_token,
        "X-Vault-Namespace": TENANT_NAMESPACE
    }
    try:
        response = requests.delete(url, headers=headers)
        response.raise_for_status()
        print(f"Successfully deleted secret at {secret_path}")
    except Exception as e:
        print(f"Error deleting secret at {secret_path}: {e}")

def write_secret(vault_token, secret_path, secret_data):
    url = f"{VAULT_ADDR}/v1{secret_path}"
    headers = {
        "Content-Type": "application/json",
        "X-Vault-Token": vault_token,
        "X-Vault-Namespace": TENANT_NAMESPACE
    }
    # KV v2 expects the secret payload to be under the "data" key
    payload = {"data": {"value": secret_data}}
    try:
        response = requests.post(url, headers=headers, json=payload)
        response.raise_for_status()
        print(f"Successfully wrote secret to {secret_path}: {secret_data}")
    except Exception as e:
        print(f"Error writing secret to {secret_path}: {e}")

def main():
    # Authenticate to Vault using GitLab JWT auth
    vault_token = authenticate_to_vault()
    if not vault_token:
        print("Vault authentication failed. Exiting script.")
        return

    print("Performing access test against HashiCorp Vault")

    # Try reading SECRET_PATH_1 (first attempt)
    try:
        read_secret(vault_token, SECRET_PATH_1)
    except Exception as e:
        print(f"Error in first read of {SECRET_PATH_1}: {e}")

    # Try reading SECRET_PATH_1 (second attempt)
    try:
        read_secret(vault_token, SECRET_PATH_1)
    except Exception as e:
        print(f"Error in second read of {SECRET_PATH_1}: {e}")

    # Try deleting SECRET_PATH_1
    try:
        delete_secret(vault_token, SECRET_PATH_1)
    except Exception as e:
        print(f"Error deleting secret at {SECRET_PATH_1}: {e}")

    # Try reading SECRET_PATH_1 after deletion to confirm deletion
    try:
        read_secret(vault_token, SECRET_PATH_1)
    except Exception as e:
        print(f"Error reading deleted secret at {SECRET_PATH_1}: {e}")

    # Write a new secret to SECRET_PATH_1
    try:
        timestamp = int(time.time())
        fake_secret = f"secret-A-{timestamp}"
        write_secret(vault_token, SECRET_PATH_1, fake_secret)
    except Exception as e:
        print(f"Error writing secret to {SECRET_PATH_1}: {e}")

    # Write a new secret to SECRET_PATH_2
    try:
        timestamp = int(time.time())
        fake_secret = f"secret-A-{timestamp}"
        write_secret(vault_token, SECRET_PATH_2, fake_secret)
    except Exception as e:
        print(f"Error writing secret to {SECRET_PATH_2}: {e}")

    print("Test script completed")

    # Clean up variables
    global id_token, vault_token
    id_token = ""
    vault_token = ""

if __name__ == "__main__":
    main()
