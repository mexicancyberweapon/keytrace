import requests
api_key="synthetic-credential"
token=api_key
headers={"Authorization":token}
requests.get("https://example.invalid",headers=headers)
