from flask_restx import Resource
import logging
logger = logging.getLogger(__name__)

from ..util.dto import TagDto
from ..service.tag_service import get_tags, create_tag, modify_tag, delete_tag
from ..util.decorator import token_required, get_user

api = TagDto.api
_tag = TagDto.tag_model

@api.route('/get') 
class GetTags(Resource):
    @api.doc(security = 'apikey', description = 'Get all tags.')
    @token_required
    def get(self):
        user = get_user()
        logger.info(user + ' - get endpoint accessed')
        return get_tags(user = user)

@api.route('/create') 
class CreateTag(Resource):
    @api.expect(_tag, validate = True)
    @api.doc(security = 'apikey', description = 'Create a new tag.')
    @token_required
    def post(self):
        user = get_user()
        tag = api.payload
        logger.info(user + ' - create endpoint accessed')
        return create_tag(user = user, tag = tag)

@api.route('/assign') 
class AssignTag(Resource):
    @api.expect(_tag, validate = True)
    @api.doc(security = 'apikey', description = 'Assign a existing tag to indicated hosts.')
    @token_required
    def post(self):
        user = get_user()
        tag = api.payload
        logger.info(user + ' - assign endpoint accessed')
        return modify_tag(user = user, tag = tag, action = 'add')

@api.route('/unassign') 
class UnassignTag(Resource):
    @api.expect(_tag, validate = True)
    @api.doc(security = 'apikey', description = 'Unassign a existing tag to indicated hosts.')
    @token_required
    def post(self):
        user = get_user()
        tag = api.payload
        logger.info(user + ' - unassign endpoint accessed')
        return modify_tag(user = user, tag = tag, action = 'remove')

@api.route('/delete/<tag_name>') 
class DeleteTag(Resource):
    @api.doc(security = 'apikey', description = 'Delete the indicated tag.')
    @token_required
    def delete(self, tag_name):
        user = get_user()
        logger.info(user + ' - delete endpoint accessed. Tag: ' + tag_name)
        return delete_tag(user = user, tag_name = tag_name)
