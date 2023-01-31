import os

class APIConfig:
    API_VERSION = 'v1'
    API_TITLE = 'VulnAna API'
    API_DESCRIPTION = 'API to interact with Greenbone Vulnerability Management and send vulnerability related data to Elasticsearch.'
    API_PREFIX = '/api/'+API_VERSION+'/'
    API_DOC = '/api/'+API_VERSION+'/'
    API_AUTHORIZATIONS = {
        'apikey' : {
            'type' : 'apiKey',
            'in' : 'header',
            'name' : 'X-API-KEY'
        }
    }
    API_LICENSE = 'AGPL-3.0'

class Config:
    SECRET_KEY = os.getenv('APP_SECRET_KEY')
    CONFIG_DECRYPT_KEY = os.getenv('CONFIG_DECRYPT_KEY')
    DEBUG = False
    SWAGGER_UI_DOC_EXPANSION = 'none'

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    DEBUG = True
    TESTING = True

class ProductionConfig(Config):
    DEBUG = False

config_by_name = dict(
    dev = DevelopmentConfig,
    test = TestingConfig,
    prod = ProductionConfig
)

KEY = Config.SECRET_KEY
CONFIG_KEY = Config.CONFIG_DECRYPT_KEY
BASEDIR = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
