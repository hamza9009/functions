import azure.functions as func
import json
import jwt  # PyJWT package for token decoding
import requests
from os import getenv

# Load environment variables
TENANT_ID = getenv("TENANT_ID")
CLIENT_ID = getenv("CLIENT_ID")
CLIENT_SECRET = getenv("CLIENT_SECRET")

AUTHORITY = f"https://login.microsoftonline.com/{TENANT_ID}"
TOKEN_URL = f"{AUTHORITY}/oauth2/v2.0/token"

def validate_access_token(access_token):
    """
    Validate the Azure AD access token using Microsoft Graph API.
    """
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get("https://graph.microsoft.com/v1.0/me", headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        return None

def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function to authenticate users using Azure AD.
    """
    try:
        req_body = req.get_json()
        access_token = req_body.get("access_token")

        if not access_token:
            return func.HttpResponse(
                json.dumps({"error": "Access token is required"}),
                status_code=400,
                mimetype="application/json"
            )

        user_info = validate_access_token(access_token)

        if user_info:
            return func.HttpResponse(
                json.dumps({"message": "Authentication successful", "user": user_info}),
                status_code=200,
                mimetype="application/json"
            )
        else:
            return func.HttpResponse(
                json.dumps({"error": "Invalid token"}),
                status_code=401,
                mimetype="application/json"
            )

    except Exception as e:
        return func.HttpResponse(
            json.dumps({"error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )