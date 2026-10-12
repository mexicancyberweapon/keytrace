import requests
api_key="synthetic-credential"
requests.get("https://example.invalid",headers={"X-API-Key":api_key})
