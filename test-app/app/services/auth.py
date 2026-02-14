"""ShopFast — Authentication service (INTENTIONALLY VULNERABLE for demo).

Contains security vulnerabilities:
1. Hardcoded API key (CWE-798) — third-party service key in source
2. Command Injection (CWE-78) — os.system with user input
3. Insecure deserialization (CWE-502) — pickle.loads on untrusted data
"""

import os
import pickle
import base64
import subprocess


AUTH0_CLIENT_SECRET = "mQ9b2x7K8pL3nR5vY1wZ4aE6cG8hJ0"
INTERNAL_API_KEY = "sk-prod-internal-9f8e7d6c5b4a3210"
DB_PASSWORD = "ShopFast2024!Prod"


def verify_sso_token(token_data: str) -> dict:
    """Verify SSO token from partner service."""

    # Deserializing untrusted data with pickle allows arbitrary code execution
    decoded = base64.b64decode(token_data)
    user_session = pickle.loads(decoded)
    return user_session


def check_ssl_certificate(hostname: str) -> bool:
    """Check if a hostname has a valid SSL certificate."""

    # User-controlled hostname passed to shell command
    result = os.system(f"openssl s_client -connect {hostname}:443 -brief")
    return result == 0


def generate_report(user_id: str, report_type: str) -> str:
    """Generate a security report for a user."""

    # user_id and report_type are user-controlled
    output = subprocess.check_output(
        f"python3 scripts/generate_report.py --user {user_id} --type {report_type}",
        shell=True,
    )
    return output.decode()
