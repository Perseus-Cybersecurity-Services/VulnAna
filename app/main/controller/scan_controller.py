from flask import request
from flask_restx import Resource
import logging
logger = logging.getLogger(__name__)

from ..util.dto import ScanDto
from ..service.scan_service import get_scan_status, connect_to_gvm
from ..util.decorator import token_required, get_user

api = ScanDto.api

@api.route('/run/<task_name>')
class RunScan(Resource):
    @api.doc(security = 'apikey', description = 'Run indicated scan.')
    @token_required    
    def get(self, task_name):
        user = get_user()
        logger.info(user + ' - run endpoint accessed. Task: ' + task_name)
        if len(task_name.split('-')) != 3 or task_name.split('-')[0] != user or task_name.split('-')[1] not in ['external', 'internal']:
            return {'message' : 'Incorrect task_name'}, 400
        return connect_to_gvm(user = user, task_name = task_name, action = 'run')

@api.route('/status')
class StatusScan(Resource):
    @api.doc(security = 'apikey', description = 'Check all scans status.')
    @token_required    
    def get(self):
        user = get_user()
        logger.info(user + ' - status endpoint accessed')
        return get_scan_status(user = user)

@api.route('/delete/<task_name>')
class DeleteScan(Resource):
    @api.doc(security = 'apikey', description = 'Delete indicated scan.')
    @token_required
    def delete(self, task_name):
        user = get_user()
        logger.info(user + ' - delete endpoint accessed. Task: ' + task_name)
        if len(task_name.split('-')) != 3 or task_name.split('-')[0] != user or task_name.split('-')[1] not in ['external', 'internal']:
            logger.info(user + ' - incorrect task_name inserted: ' + task_name)
            return {'message' : 'Incorrect task_name'}, 400
        return connect_to_gvm(user = user, task_name = task_name, action = 'delete')
        
