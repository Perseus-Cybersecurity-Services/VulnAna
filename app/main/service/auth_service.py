from datetime import datetime, timedelta
import jwt
import logging
logger = logging.getLogger(__name__)

from ..config.app_config import KEY

def encode_token(user):
    try:
        payload = {
            'exp': datetime.now() + timedelta(minutes = 15),
            'iat': datetime.now(),
            'user': user
        }
        token = jwt.encode(
            payload,
            KEY,
            algorithm='HS256'
        )
        logger.info(user + ' - token generated successfully')
        return {'token' : token}, 201
    except Exception as e:
        logger.error(user + ' - token generation failed')
        return {'message' : 'Token generation failed'}, 500
        