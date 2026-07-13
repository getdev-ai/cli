from fastapi import APIRouter

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.get("/users/{user_id}")
def get_user(user_id: int):
    return {"id": user_id}


@router.post("/users")
def create_user(payload: dict):
    return {"created": True}
