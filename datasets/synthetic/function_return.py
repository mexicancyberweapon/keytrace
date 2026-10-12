import requests
def wrap(value):
 return "Bearer " + value
api_key="synthetic-credential"
requests.get("https://example.invalid",headers={"Authorization":wrap(api_key)})
