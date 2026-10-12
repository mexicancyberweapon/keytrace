import requests
def send(value):
 requests.get("https://example.invalid",auth=value)
api_key="synthetic-credential"
send(api_key)
