#!/usr/bin/env python3
from flask import Flask, abort, jsonify, request
from auth import Auth


AUTH = Auth()
app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def index():
    """the index route handler"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def users():
    """end-point to register a user"""
    email = request.form.get("email")
    password = request.form.get("password")
    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    if user:
        return jsonify({"email": user.email, "message": "user created"})


@app.route('/login', methods=['POST'], strict_slashes=False)
def login():
    """ create a new session for the user, store it the session ID
    as a cookie with key "session_id" on the response and
    return a JSON payload of the form.
    """
    email = request.form.get("email")
    password = request.form.get("password")
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    resp = jsonify({"email": f"{email}", "message": "logged in"})
    resp.set_cookie("session_id", session_id)
    return resp


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
