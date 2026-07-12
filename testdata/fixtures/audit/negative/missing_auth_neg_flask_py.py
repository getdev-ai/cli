from flask import Flask
from flask_login import login_required

app = Flask(__name__)


@app.route("/admin")
@login_required
def admin():
    return {"secret": "admin data"}
