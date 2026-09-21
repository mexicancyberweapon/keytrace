import requests

api_key = "deez_nuts"
token = api_key

headers = {
    "Authorization": token
}

requests.get(
    "https://deeznuts.com",
    headers=headers
)
