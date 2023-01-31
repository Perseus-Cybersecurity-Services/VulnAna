from flask_restx import Namespace, fields
from datetime import datetime, timedelta

IPV4_PATTERN = '^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

class AuthDto:
    api = Namespace('auth', description='Authentication Related Operations')

class CoreDto:
    api = Namespace('vulnana', description='VulnAna Core Operations')

class ScanDto:
    api = Namespace('scan', description='Scan Related Operations')

class TagDto:
    api = Namespace('tag', description='Tag Related Operations')
    tag_model = api.model('Tag', {
        'key' : fields.String(
            required=True, 
            description='tag descriptor',
            max_length=50),  
        'value' : fields.Integer(
            required=False, 
            description='OPTIONAL, tag value',
            min=0,
            max=1000),
        'target_IPs' : fields.List(
            fields.String(
                required=True, 
                description='0.0.0.0',
                pattern=IPV4_PATTERN,
                example= '0.0.0.0'
                ), 
            required=False, 
            description='IP list'),
        'target_subnets' : fields.List(
            fields.String(
                required=True, 
                description='192.168.0.0/24',
                example= '192.168.0.0/24'
                ), 
            required=False, 
            description='IP subnet list') 
        })
