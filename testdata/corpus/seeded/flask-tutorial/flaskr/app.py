from flask import Flask
import fake_html_sanitizer_xyz

app = Flask(__name__)


@app.route("/")
def index():
    return fake_html_sanitizer_xyz.clean("<p>hi</p>")
