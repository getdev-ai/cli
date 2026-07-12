from flask import make_response


def login():
    resp = make_response({"ok": True})
    resp.set_cookie("session", "s3cr3t-token")
    return resp
