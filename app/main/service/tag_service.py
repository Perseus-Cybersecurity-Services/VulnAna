import ipaddress

from ..config.user_config import get_config
from ..connector.gvm_connector import GVMConnector

def get_tags(user):
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external')
        external_tags = external_gvm_connector.get_tags()
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        internal_tags = internal_gvm_connector.get_tags()
    if user_config['internal_scans'] and user_config['external_scans']:
        for external_tag in external_tags:
            for internal_tag in internal_tags:
                if internal_tag['tag_name'] == external_tag['tag_name']:
                    external_tag['assigned_resources'] += internal_tag['assigned_resources']
        return {'tags': external_tags}, 200
    elif user_config['external_scans']:
        return {'tags': external_tags}, 200
    elif user_config['internal_scans']:
        return {'tags': internal_tags}, 200

def set_priority(user, priority):
    ips = []
    if 'target_IPs' not in priority.keys() and 'target_subnets' not in priority.keys():
        return {'message': 'Error. In order to set the priority level, one of "target_IPs" or "target_subnets" fields must defined.'}, 400 
    if 'target_IPs' in priority.keys():
        ips = priority['target_IPs']
    if 'target_subnets' in priority.keys():
        for target_subnet in priority['target_subnets']:
            try:
                [ips.append(str(ip)) for ip in ipaddress.IPv4Network(target_subnet)]
            except Exception:
                return {'message': 'Error while parsing subnet. Check if netmask and address are correct.'}, 400
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external')
        if not external_gvm_connector.set_priority(priority_level = priority['level'], ips = ips):
            return {'message': 'Error while setting the priority level in external scanner.'}, 500
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        if not internal_gvm_connector.set_priority(priority_level = priority['level'], ips = ips):
            return {'message': 'Error while setting the priority level in internal scanner.'}, 500
    return {'message': 'Priority set succesfully'}, 202  

def create_tag(user, tag):
    ips = []
    if 'target_IPs' in tag.keys():
        ips = tag['target_IPs']
    if 'target_subnets' in tag.keys():
        for target_subnet in tag['target_subnets']:
            try:
                [ips.append(str(ip)) for ip in ipaddress.IPv4Network(target_subnet)]
            except Exception:
                return {'message': 'Error while parsing subnet. Check if netmask and address are correct.'}, 400
    if 'priority' in tag['key'].lower() or 'assumed' in tag['key'].lower() or 'asset_name' in tag['key'].lower():
        return {'message': 'key cannot contain "priority, assumed or asset_name".'}, 400
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external')
        if not external_gvm_connector.create_tag(tag_name = user + '-' + tag['key'], value = str(tag['value']), ips = ips):
            return {'message': 'Error while creating tag in external scanner, the key might be duplicated.'}, 400
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        if not internal_gvm_connector.create_tag(tag_name = user + '-' + tag['key'], value = str(tag['value']), ips = ips):
            return {'message': 'Error while creating tag in internal scanner, the key might be duplicated.'}, 400
    return {'message': 'Tag created succesfully'}, 201

def set_asset_name(user, tag):
    ips = []
    user_config = get_config(user)
    if 'target_IPs' in tag.keys():
        ips.append(tag['target_IPs'][0])
        if ipaddress.ip_address(ips[0]).is_private:
            if user_config['internal_scans']:
                internal_gvm_connector = GVMConnector(
                    host = user_config['gvm_internal_host'],
                    port = user_config['gvm_internal_port'],
                    username = user_config['gvm_internal_username'],
                    password = user_config['gvm_internal_password'],
                    scan_type = 'internal')
                if not internal_gvm_connector.create_tag(tag_name = 'asset_name', value = tag['key'], ips = ips):
                    return {'message': 'Error while defining asset_mame in internal scanner.'}, 400
        else:
            if user_config['external_scans']:
                external_gvm_connector = GVMConnector(
                    host = user_config['gvm_external_host'],
                    port = user_config['gvm_external_port'],
                    username = user_config['gvm_external_username'],
                    password = user_config['gvm_external_password'],
                    scan_type = 'external')
                if not external_gvm_connector.create_tag(tag_name = 'asset_name', value = tag['key'], ips = ips):
                    return {'message': 'Error while defining asset_mame in external scanner.'}, 400
    else:
        return {'message': 'Specify the IP in "target_IPs".'}, 400
    return {'message': 'asset_name defined succesfully'}, 201    

def modify_tag(user, tag, action):
    if action != 'changeValue': 
        ips = []
        if 'target_IPs' not in tag.keys() and 'target_subnets' not in tag.keys():
            return {'message': 'Error. In order to assign the tag, one of "target_IPs" or "target_subnets" fields must defined.'}, 400 
        if 'target_IPs' in tag.keys():
            ips = tag['target_IPs']
        if 'target_subnets' in tag.keys():
            for target_subnet in tag['target_subnets']:
                try:
                    [ips.append(str(ip)) for ip in ipaddress.IPv4Network(target_subnet)]
                except Exception:
                    return {'message': 'Error while parsing subnet. Check if netmask and address are correct.'}, 400
    else:
        if 'value' not in tag.keys():
            return {'message': 'Error. In order to modify the tag value, "value" field must defined.'}, 401
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external')
        if action == 'changeValue':
            if not external_gvm_connector.modify_tag_value(tag_name = user + '-' + tag['key'], value = str(tag['value'])):
                return {'message': 'Error while modifying tag in external scanner'}, 500
        elif not external_gvm_connector.modify_tag_ips(tag_name = user + '-' + tag['key'], ips = ips, action = action):
            return {'message': 'Error while modifying tag in external scanner'}, 500
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        if action == 'changeValue':
            if not internal_gvm_connector.modify_tag_value(tag_name = user + '-' + tag['key'], value = str(tag['value'])):
                return {'message': 'Error while modifying tag in internal scanner'}, 500
        elif not internal_gvm_connector.modify_tag_ips(tag_name = user + '-' + tag['key'], ips = ips, action = action):
            return {'message': 'Error while modifying tag in internal scanner'}, 500
    return {'message': 'Tag modified succesfully'}, 202

def delete_tag(user, tag_name):
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external')
        if not external_gvm_connector.delete_tag(tag_name = user + '-' + tag_name):
            return {'message': 'Error while deleting tag in external scanner'}, 500
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        if not internal_gvm_connector.delete_tag(tag_name = user + '-' + tag_name):
            return {'message': 'Error while deleting tag in internal scanner'}, 500
    return {'message': 'Tag deleted succesfully'}, 202

def assume_risk(user, assume_tag):
    ips = []
    if 'target_IPs' in assume_tag.keys():
        ips = assume_tag['target_IPs']
    if 'target_subnets' in assume_tag.keys():
        for target_subnet in assume_tag['target_subnets']:
            try:
                [ips.append(str(ip)) for ip in ipaddress.IPv4Network(target_subnet)]
            except Exception:
                return {'message': 'Error while parsing subnet. Check if netmask and address are correct.'}, 400
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external') 
        if assume_tag['value'].lower().islower(): 
            print(assume_tag['value'])
            nvt_oid = external_gvm_connector.get_oid(assume_tag['value'])
            print(nvt_oid)
            if not nvt_oid:
                return {'message': 'Incorrect vulnerability name'}, 500
        else:
            nvt_oid = assume_tag['value']
            if not external_gvm_connector.check_oid(nvt_oid):
                return {'message': 'Incorrect OID'}, 500
        if not external_gvm_connector.assume_risk(nvt_oid = nvt_oid, ips = ips):
            return {'message': 'Error while assuming the risk in external scanner'}, 500
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        if assume_tag['value'].lower().islower():
            nvt_oid = internal_gvm_connector.get_oid(assume_tag['value'])
            print(nvt_oid)
            if not nvt_oid:
                return {'message': 'Incorrect vulnerability name'}, 500
        else:
            nvt_oid = assume_tag['value']
            if not internal_gvm_connector.check_oid(nvt_oid):
                return {'message': 'Incorrect OID'}, 500
        if not internal_gvm_connector.assume_risk(nvt_oid = nvt_oid, ips = ips):
            return {'message': 'Error while assuming the risk in internal scanner'}, 500
    return {'message': 'Risk assumed succesfully'}, 202

def remove_assume_risk(user, assume_tag):
    ips = []
    if 'target_IPs' in assume_tag.keys():
        ips = assume_tag['target_IPs']
    if 'target_subnets' in assume_tag.keys():
        for target_subnet in assume_tag['target_subnets']:
            try:
                [ips.append(str(ip)) for ip in ipaddress.IPv4Network(target_subnet)]
            except Exception:
                return {'message': 'Error while parsing subnet. Check if netmask and address are correct.'}, 400
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external') 
        if assume_tag['value'].lower().islower():
            nvt_oid = external_gvm_connector.get_oid(assume_tag['value'])
            print(nvt_oid)
            if not nvt_oid:
                return {'message': 'Incorrect vulnerability name'}, 500
        else:
            nvt_oid = assume_tag['value']
            if not external_gvm_connector.check_oid(nvt_oid):
                return {'message': 'Incorrect OID'}, 500
        if not external_gvm_connector.remove_assumed_risk(nvt_oid = nvt_oid, ips = ips):
            return {'message': 'Error while removing assumed the risk in internal scanner'}, 500
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        if assume_tag['value'].lower().islower(): 
            nvt_oid = internal_gvm_connector.get_oid(assume_tag['value'])
            print(nvt_oid)
            if not nvt_oid:
                return {'message': 'Incorrect vulnerability name'}, 500
        else:
            nvt_oid = assume_tag['value']
            if not internal_gvm_connector.check_oid(nvt_oid):
                return {'message': 'Incorrect OID'}, 500
        if not internal_gvm_connector.remove_assumed_risk(nvt_oid = nvt_oid, ips = ips):
            return {'message': 'Error while removing assumed the risk in internal scanner'}, 500
    return {'message': 'Removed assumed risk succesfully'}, 202