import requests
api_key="placeholder"
h={"Authorization":api_key}
h["Authorization"]=""
requests.get("https://example.invalid",headers=h)
