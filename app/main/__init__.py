from flask import Flask
from flask_restx import Api
from flask import Blueprint

from .config.app_config import config_by_name
from .controller.auth_controller import api as auth_ns
from .controller.scan_controller import api as scan_ns
from .controller.tag_controller import api as tag_ns
from .controller.core_controller import api as core_ns
from .config.app_config import APIConfig

import logging
import logging.handlers

from .config.app_config import BASEDIR

def config_logging(app):
      del app.logger.handlers[:]
      logger = app.logger
      if app.config['DEBUG']:
            console_handler  = logging.StreamHandler()
            console_handler.setLevel(logging.DEBUG)
            console_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
            console_handler.setFormatter(console_format)
            logger.addHandler(console_handler)
      else:
            gunicorn_logger = logging.getLogger('gunicorn.error')
            app.logger.handlers = gunicorn_logger.handlers
            app.logger.setLevel(gunicorn_logger.level)
            file_handler = logging.handlers.TimedRotatingFileHandler(filename= BASEDIR + '/logs/vulnana.log', when='D', interval=1, backupCount=7)
            file_handler.setLevel(logging.INFO)
            file_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
            file_handler.setFormatter(file_format)
            logger.addHandler(file_handler)

def create_app(config_name):
      app = Flask(__name__)
      app.config.from_object(config_by_name[config_name])
      blueprint = Blueprint('api', __name__) 
      
      api = Api(app = blueprint,
            title = APIConfig.API_TITLE,
            version = APIConfig.API_VERSION,
            authorizations = APIConfig.API_AUTHORIZATIONS,
            description = APIConfig.API_DESCRIPTION,
            prefix = APIConfig.API_PREFIX,
            doc = APIConfig.API_DOC,
            license = APIConfig.API_LICENSE
      )
      api.add_namespace(auth_ns, path='/auth')
      api.add_namespace(scan_ns, path='/scan')
      api.add_namespace(tag_ns, path='/tag')
      api.add_namespace(core_ns, path='/vulnana')
      app.register_blueprint(blueprint)
      config_logging(app)
      app.logger.info('App initialized')
      return app