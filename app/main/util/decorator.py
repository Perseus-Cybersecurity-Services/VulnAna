from functools import wraps
from flask import request
import jwt

from ..config.app_config import KEY

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):

        token = None

        if 'X-API-KEY' in request.headers:
            token = request.headers['X-API-KEY']

        if not token:
            return {'message' : 'Token is missing.'}, 401
        try:
            jwt.decode(token, KEY, algorithms=['HS256'])
        except Exception:
            return {'message' : 'Token is invalid.'}, 401

        return f(*args, **kwargs)

    return decorated

def get_user():
    return jwt.decode(request.headers['X-API-KEY'], KEY, algorithms=['HS256'])['user']