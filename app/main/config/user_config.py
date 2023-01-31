from .app_config import BASEDIR, CONFIG_KEY
from configparser import ConfigParser
from cryptography.fernet import Fernet

CONFIGDIR = BASEDIR + '/config/user_config.ini'

def get_companies(file_path: str):
    companies = []
    config = ConfigParser()
    try: 
        config.read(file_path) 
        for section in config.sections():
            companies.append(section)
    except Exception as e:
        print(e)
        return False
    return companies

def get_config(company):
    config_dict = {}
    fields = ['internal_scans', 'external_scans', 'gvm_external_host', 'gvm_external_port', 
        'gvm_external_username', 'gvm_external_password', 'gvm_internal_host', 'gvm_internal_port', 
        'gvm_internal_username', 'gvm_internal_password', 'elasticsearch_host', 'elasticsearch_port', 
        'elasticsearch_username', 'elasticsearch_password', 'elastic_use_certs']
    try:
        if validate_section(CONFIGDIR, company, fields):
            config_dict = read_encrypted_section(CONFIGDIR, company, CONFIG_KEY)
            if config_dict['external_scans'].lower() == 'true':
                config_dict['external_scans'] = True
            else:
                config_dict['external_scans'] = False
            if config_dict['internal_scans'].lower() == 'true':
                config_dict['internal_scans'] = True
            else:
                config_dict['internal_scans'] = False
            if config_dict['elastic_use_certs'].lower() == 'true':
                config_dict['elastic_use_certs'] = True
            else:
                config_dict['elastic_use_certs'] = False
        else:
            print('At least one field of user config is missing.')
            return False
    except Exception as e:
        print(e)
        return False
    return config_dict

def validate_section(file_path: str, section: str, fields: list):
    config = ConfigParser()
    config.read(file_path)
    if section in config.sections():
        for field in fields:
            if field not in config[section]:
                print('field "' + field + '" not defined in section "' + section + '"')
                return False
        return True
    else:
        print('section "' + section + '" not defined in "' + file_path + '"')
        return False

def read_encrypted_section(file_path: str, section: str, sym_key: str):
    section_dict = {}
    config = ConfigParser()
    config.read(file_path)
    if section in config.sections():
        for key in config[section]:
            if config[section][key].startswith('encrypted_'):
                section_dict[key] = p3_decrypt(config[section][key], sym_key)
            else:
                section_dict[key] = config[section][key]
        return section_dict
    else:
        print('section "' + section + '" not defined in ' + file_path)
    
def p3_encrypt(message: bytes, key: bytes):
    return 'encrypted_' + Fernet(key).encrypt(message).decode()

def p3_decrypt(token: str, key: bytes):
    return Fernet(key).decrypt(token.split('encrypted_')[1].encode()).decode()


