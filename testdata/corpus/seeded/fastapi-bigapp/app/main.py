from fastapi import FastAPI
from acme_api_client import missing_method

app = FastAPI()
model_name = "gpt5-turbo-hallucinated"


@app.get("/")
async def root():
    return {"result": missing_method(), "model": model_name}
