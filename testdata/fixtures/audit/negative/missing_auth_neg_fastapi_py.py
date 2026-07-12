from fastapi import Depends, FastAPI

app = FastAPI()


def verify_token():
    pass


@app.get("/admin", dependencies=[Depends(verify_token)])
def get_admin():
    return {"secret": "admin data"}
