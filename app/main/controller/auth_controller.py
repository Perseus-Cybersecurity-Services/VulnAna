from flask import request
from flask_restx import Resource
import logging
logger = logging.getLogger(__name__)

from ..util.dto import AuthDto
from ..service.auth_service import encode_token
from ..util.decorator import token_required, get_user

api = AuthDto.api

@api.route('/login')
class UserLogin(Resource):
    @api.doc(description = 'User login.')
    def post(self):
        auth = request.authorization 
        if auth == None:
            logger.info('someone tried to authenticate without credentials')
            return {'message' : 'Auth is required'}, 403
        else:
            logger.info(auth['username'] +' - successfully authenticated')
            return encode_token(user = auth['username'])

@api.route('/refreshToken')
class RefreshToken(Resource):
    @api.doc(security = 'apikey', description = 'Refresh the token.')
    @token_required
    def post(self):
        user = get_user()
        logger.info(user +' - token refreshed')
        return encode_token(user = user)
        