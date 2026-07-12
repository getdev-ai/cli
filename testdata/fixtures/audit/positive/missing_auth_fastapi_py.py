from fastapi import FastAPI

app = FastAPI()


@app.get("/admin")
def get_admin():
    return {"secret": "admin data"}
