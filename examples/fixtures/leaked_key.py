"""Fixture: kredensial palsu untuk memancing Gitleaks. Bukan kunci asli."""

AWS_ACCESS_KEY_ID = "AKIAQYLPMN5HNXWTQ7ZR"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI2K7MDENGbPxRfiCYEXAMPLEKEY9z"


def client_config():
    return {
        "aws_access_key_id": AWS_ACCESS_KEY_ID,
        "aws_secret_access_key": AWS_SECRET_ACCESS_KEY,
    }
