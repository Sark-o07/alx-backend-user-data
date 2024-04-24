#!/usr/bin/env python3
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def index():
    """the index route handler"""
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
