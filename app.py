# Python標準ライブラリ
import json
import os
import sqlite3

# サードパーティライブラリ
from flask import Flask, redirect, request, url_for
from flask_login import (
    LoginManager,
    current_user,
    login_required,
    login_user,
    logout_user,
)
from oauthlib.oauth2 import WebApplicationClient
import requests

# 内部インポート
from db import init_db_command
from user import User

# 設定情報
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Flaskセットアップ
app = Flask(__name__)
#セッション情報を暗号化するためのキーを設定
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# ユーザセッション管理の設定
# https://flask-login.readthedocs.io/en/latest
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.unauthorized_handler
def unauthorized():
    return "You must be logged in to access this content.", 403


# データベースの初期化
try:
    init_db_command()
except sqlite3.OperationalError:
    # すでに作成されている場合は、何もしない
    pass

# OAuth2クライアント設定
client = WebApplicationClient(GOOGLE_CLIENT_ID)

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)


@app.route("/")
def index():
    if current_user.is_authenticated:
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<a class="button" href="/logout">Logout</a>'.format(
                current_user.name, current_user.email, current_user.profile_pic
            )
        )
    else:
        return '<a class="button" href="/login">Google Login</a>'


@app.route("/login")
def login():
    # 認証用のエンドポイントを取得する
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # ユーザプロファイルを取得するログイン要求
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Googleから返却された認証コードを取得する
    code = request.args.get("code")

    #トークンを取得するためのURLを取得する
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    # トークンを取得するための情報を生成し、送信する
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # トークンをparse
    client.parse_request_body_response(json.dumps(token_response.json()))

    # トークンができたので、GoogleからURLを見つけてヒットした、
    # Googleプロフィール画像やメールなどのユーザーのプロフィール情報を取得
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # メールが検証されていれば、名前、email、プロフィール画像を取得します
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
    else:
        return "User email not available or not verified by Google.", 400

    # Googleから提供された情報をもとに、Userを生成する
    user = User(
        id_=unique_id, name=users_name, email=users_email, profile_pic=picture
    )

    # 登録されていない場合は、データベースへ登録する
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture)

    # ログインしてユーザーセッションを開始
    login_user(user)

    return redirect(url_for("index"))


# @login_requiredデコレータは認証したいページに付ける
@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("index"))


def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()


if __name__ == "__main__":
    app.run(ssl_context="adhoc")
