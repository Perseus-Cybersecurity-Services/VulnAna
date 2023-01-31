from flask import request
from flask_restx import Resource
import logging
logger = logging.getLogger(__name__)

from ..util.dto import CoreDto
from ..service.core_service import exec_vulnana
from ..util.decorator import token_required, get_user

api = CoreDto.api

@api.route('/finished/<task_name>', doc = False)
class Trigger(Resource):
    def get(self, task_name):
        if len(task_name.split('-')) != 3 or task_name.split('-')[1] not in ['external', 'internal']:
            logger.info('task_name: ' + task_name + ' is incorrect')
            return {'message' : 'Incorrect task_name'}, 401
        user = task_name.split('-')[0]
        logger.info(user + ' - ' + task_name + ' has finished')
        return exec_vulnana(user = user)

@api.route('/inject') 
class Inject(Resource):
    @api.doc(security = 'apikey', description = 'Inject all scans (if completed) to ElasticSearch.')
    @token_required
    def get(self):
        user = get_user()
        logger.info(user + ' - scan injection forced')
        return exec_vulnana(user = user)
        