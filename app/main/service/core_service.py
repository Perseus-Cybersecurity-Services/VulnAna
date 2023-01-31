from time import strftime, strptime
import logging
logger = logging.getLogger(__name__)

from ..config.user_config import get_config
from ..connector.gvm_connector import GVMConnector
from ..connector.elastic_connector import ElasticConnector
from ..connector.file_connector import get_processed_reports, save_report_id
from ..util.unifier import process_reports, organize_reports
from ..util.scorer import Scorer

ORIGINAL_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
CUT_DATE_FORMAT = '%Y-%m-%d'

def exec_vulnana(user):
    scans = []
    user_config = get_config(user)

    elastic_connector = ElasticConnector(
        user_config['elasticsearch_host'],
        user_config['elasticsearch_port'],
        user_config['elasticsearch_username'],
        user_config['elasticsearch_password'],
        user_config['elastic_use_certs'],
        user_config['elastic_ca_cert'],
        user_config['elastic_client_cert'],
        user_config['elastic_client_key'])
    connectivity = elastic_connector.check_connectivity()
    if not connectivity:
        logger.error(user + ' - no connectivity with elasticsearch')
        return {'message':'No connectivity with elasticsearch. Information not sent.'}, 503
    logger.info(user + ' - connectivity with elasticsearch has been checked successfully')

    if user_config['external_scans']:
        external_gvm_connector = GVMConnector(
            host = user_config['gvm_external_host'],
            port = user_config['gvm_external_port'],
            username = user_config['gvm_external_username'],
            password = user_config['gvm_external_password'],
            scan_type = 'external'
        )
        scans.extend(external_gvm_connector.check_status(user))
    if user_config['internal_scans']:
        internal_gvm_connector = GVMConnector(
            host = user_config['gvm_internal_host'],
            port = user_config['gvm_internal_port'],
            username = user_config['gvm_internal_username'],
            password = user_config['gvm_internal_password'],
            scan_type = 'internal'
        )
        scans.extend(internal_gvm_connector.check_status(user))

    processed_reports = get_processed_reports(user)
    for scan in scans:
        if scan['last_report_id'] in processed_reports or scan['status'] != 'Done':
            logger.info(user + ' - at least one scan of your company is not ready yet')
            return {'message':'At least one scan of your company is not ready yet. For more information check /scan/status'}, 200
    reports = []
    all_results = []
    assets = []
    for scan in scans:
        if scan['type'] == 'external':
            temp_report, temp_results, temp_assets = external_gvm_connector.fetch_delta_report(scan['last_report_id'])
        elif scan['type'] == 'internal':
            temp_report, temp_results, temp_assets = internal_gvm_connector.fetch_delta_report(scan['last_report_id'])
        reports.append(temp_report)
        all_results.extend(temp_results)
        assets.extend(temp_assets)

    logger.info(user + ' - report info fetched')

    reports = process_reports(assets, reports)
    assets, all_results, reports = Scorer(user, assets, all_results, reports).run()
    logger.info(user + ' - report info processed')
    
    results = []
    for result in all_results:
        if result['delta'] != 'gone':
            results.append(result)

    send_data_elastic(user, elastic_connector, reports, assets, results)
    save_report_id(user = user, ids = reports['report_ids'])

    logger.info(user + ' - scan info sent to Elasticsearch')  

    return {'message':'All scans info sent to Elasticsearch'}, 202

def send_data_elastic(user, elastic_connector, reports, assets, results):
    if not elastic_connector.send_assets(assets, 'vulnana_assets_'+ strftime(CUT_DATE_FORMAT, strptime(reports['timestamp'], ORIGINAL_DATE_FORMAT))): 
        logger.error(user + ' - failed to info send assets info to Elasticsearch')  
        return {'message':'An error ocurred while sending assets info to Elasticsearch'}, 500
    
    if not elastic_connector.send_report(reports, 'vulnana_reports_' + strftime(CUT_DATE_FORMAT, strptime(reports['timestamp'], ORIGINAL_DATE_FORMAT))):
        logger.error(user + ' - failed to info send report info to Elasticsearch')
        return {'message':'An error ocurred while sending report info to Elasticsearch'}, 500
    
    if not elastic_connector.send_results(results, 'vulnana_results_' + strftime(CUT_DATE_FORMAT, strptime(reports['timestamp'], ORIGINAL_DATE_FORMAT))): 
        logger.error(user + ' - failed to info send results info to Elasticsearch')
        return {'message':'An error ocurred while sending results info to Elasticsearch'}, 500
