# must NOT fire: correct env-var usage, no literals
import os

stripe_key = os.environ["STRIPE_SECRET_KEY"]
api_token = os.environ.get("API_TOKEN", "")
region = "eu-west-1"
