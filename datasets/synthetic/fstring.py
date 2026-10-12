import requests
api_key="synthetic-credential"
requests.get("https://example.invalid",headers={"Authorization":f"Bearer {api_key}"})
