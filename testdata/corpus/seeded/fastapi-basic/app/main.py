from fastapi import FastAPI
import fake_analytics_sdk_xyz

app = FastAPI()


@app.get("/")
async def root():
    fake_analytics_sdk_xyz.track("root")
    return {"message": "hello"}
