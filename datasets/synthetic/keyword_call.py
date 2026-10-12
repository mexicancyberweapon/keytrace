import requests
def send(*, value):
 requests.get("https://example.invalid",auth=value)
api_key="synthetic-credential"
send(value=api_key)
