import ipaddress, dns.resolver, json
from datetime import datetime, timedelta

from ..config.user_config import get_config, get_companies
from ..connector.gvm_connector import GVMConnector
from ..connector.file_connector import get_processed_reports

def get_scan_status(user):
    scans = []
    user_config = get_config(user)
    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external')
        scans.extend(external_gvm_connector.check_status(user))
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal')
        scans.extend(internal_gvm_connector.check_status(user))

    processed_reports = get_processed_reports(user)
    completed_scans = 0
    for scan in scans:
        if 'last_report_id' in scan.keys() and scan['last_report_id'] not in processed_reports:
            scan['new_report'] = True
            if scan['status'] == 'Done':
                completed_scans += 1
        else:
            scan['new_report'] = False

    status = {}
    status['scan_quantity'] = len(scans)
    status['new_completed_scans'] = completed_scans
    status['scans'] = scans
    return {'status' : status}, 200

def connect_to_gvm(user, task_name, action):
    user_config = get_config(user)
    host = user_config['gvm_external_host']
    port = user_config['gvm_external_port'] 
    username = user_config['gvm_external_username']
    password = user_config['gvm_external_password']
    scan_type = 'external'
    if user_config['external_scans'] and task_name.split('-')[1] == 'external':
        host = user_config['gvm_external_host']
        port = user_config['gvm_external_port'] 
        username = user_config['gvm_external_username']
        password = user_config['gvm_external_password']
        scan_type = 'external'
    elif user_config['internal_scans'] and task_name.split('-')[1] == 'internal':
        host = user_config['gvm_internal_host']
        port = user_config['gvm_internal_port']
        username = user_config['gvm_internal_username']
        password = user_config['gvm_internal_password']
        scan_type = 'internal'
    else:
        return {'message':'An error ocurred, check if your company can select the scan type you chose '}, 500
    try:
        gvm_connector = GVMConnector(
            host = host,
            port = port, 
            username = username, 
            password = password,
            scan_type = scan_type)
        if action == 'run':
            if gvm_connector.run_task(task_name):
                return {'message': 'Task: ' + task_name + ' executed successfully'}, 202
            else:
                return {'message': 'An error ocurred. Task: ' + task_name + ' not executed'}, 500
        if action == 'delete':
            if gvm_connector.delete_task(task_name):
                return {'message': 'Task: ' + task_name + ' deleted successfully'}, 202
            else:
                return {'message': 'An error ocurred. Task: ' + task_name + ' not deleted'}, 500
    except Exception:
        return {'message':'An error ocurred.'}, 500