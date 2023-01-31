from asyncio import format_helpers
from gvm.connections import TLSConnection, UnixSocketConnection
from gvm.errors import GvmError
from gvm.protocols.gmpv208.entities.entities import EntityType 
from gvm.protocols.latest import Gmp 
from gvm.transforms import EtreeCheckCommandTransform
from gvm.xml import pretty_print
from icalendar import Calendar, Event
import xml.etree.ElementTree as ET
import pandas as pd
from time import strptime, strftime
from datetime import datetime
pd.options.mode.chained_assignment = None

ALL_ROWS = 'rows=-1'

class GVMConnector:
    def __init__(
        self,
        host,
        port,
        username,
        password,
        scan_type
        ):
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._scan_type = scan_type

    def check_connectivity(self):
        connection = TLSConnection(hostname = self._host, port = self._port) 
        transform = EtreeCheckCommandTransform() 
        try: 
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password) 
                gmp.get_version()
                print('Connected to '+self._scan_type+' GVM succesfully.')
                return True 
        except GvmError as e: 
            print(e) 
            print('Could not connect to '+self._scan_type+' GVM.')
            return False

    def get_all_report_ids(self, task_name):
        reports = []
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform() 
        try: 
            with Gmp(connection = connection, transform = transform) as gmp:
                gmp.authenticate(self._username, self._password) 
                reports_xml = gmp.get_reports(filter_string = 'rows=-1 ~'+task_name)
                for report in reports_xml.xpath('report'): 
                    report_dict = {}
                    report_dict['report_id'] = report.attrib['id']+'_'+self._scan_type
                    report_dict['timestamp'] = report.find('name').text
                    reports.append(report_dict)
        except GvmError as e: 
            print(e) 
            return False
        return reports

    def fetch_delta_report(self, report_id):
        report_ids = []
        asset_ids = []
        results = []
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform() 
        try: 
            with Gmp(connection = connection, transform = transform) as gmp:
                gmp.authenticate(self._username, self._password) 
                report_xml = gmp.get_report(report_id=report_id)
                for report in report_xml.xpath('report'): 
                    task_id = report.find('task').attrib['id']
                reports_xml = gmp.get_reports(filter_string = task_id + ' rows=-1')
                for report in reports_xml.xpath('report'): 
                    report_ids.append(report.attrib['id'])
                if len(report_ids) > 1 and report_ids.index(report_id) != 0 :
                    last_report_id = report_ids[report_ids.index(report_id)-1]
                else:
                    print("Couldn't get delta report. This is the first report of the task")
                    return self.fetch_report_info(report_id) 
                
                delta_report_xml = gmp.get_report(
                    report_id=last_report_id, 
                    delta_report_id=report_id,
                    filter_string = 'levels=lmh rows=-1'
                )
                for report in delta_report_xml.xpath('report'): 
                    report_dict = {} 
                    report_dict['report_id'] = report.find('report/delta/report').attrib['id'] 
                    report_dict['timestamp'] = report.find('report/delta/report/timestamp').text 
                    if not report_dict['timestamp'].endswith('Z'):
                        report_dict['timestamp'] += 'Z'
                    report_dict['task_id'] = report.find('task').attrib['id'] 
                    report_dict['task_name'] = report.find('task/name').text 
                    report_dict['scan_status'] = report.find('report/delta/report/scan_run_status').text
                    report_dict['reinjected'] = False
                
                for asset in delta_report_xml.xpath('report/report/host'):
                    asset_ids.append(asset.find('asset').attrib['asset_id']) 
                
                asset_ids = list(filter(None, asset_ids))

                assets = self.get_assets(asset_ids, report_id, report_dict['timestamp'])

                for result in delta_report_xml.xpath('report/report/results/result'):
                    if result.find('name').text != 'Report outdated / end-of-life Scan Engine / Environment (local)':
                        result_dict = {} 
                        result_dict['delta'] = result.find('delta').text
                        result_dict['report_id'] = report_id 
                        result_dict['vuln_name'] = result.find('name').text 
                        result_dict['vuln_id'] = result.attrib['id'] 
                        result_dict['timestamp'] = report_dict['timestamp']
                        if not report_dict['timestamp'].endswith('Z'):
                            result_dict['timestamp'] += 'Z'
                        result_dict['asset_ip'] = result.find('host').text 
                        result_dict['asset_name'] = result.find('host/hostname').text 
                        if result_dict['asset_name'] is None:
                            result_dict['asset_name'] = result_dict['asset_ip']
                        result_dict['port'] = result.find('port').text
                        result_dict['nvt_oid'] = result.find('nvt').attrib['oid'] 
                        result_dict['severity'] = result.find('threat').text 
                        result_dict['CVSS'] = float(result.find('severity').text) 
                        if result_dict['CVSS'] >= 9:
                            result_dict['severity'] = 'Critical'
                        nvt_info = result.find('nvt/tags').text
                        result_dict['summary'] = nvt_info.split('|')[1].split('=')[-1] 
                        result_dict['detection_result'] = result.find('description').text 
                        result_dict['insight'] = nvt_info.split('|')[2].split('=')[-1] 
                        result_dict['detection_method'] = nvt_info.split('|')[6].split('=')[-1]
                        result_dict['affected_software_os'] = nvt_info.split('|')[3].split('=')[-1] 
                        result_dict['impact'] = nvt_info.split('|')[4].split('=')[-1] 
                        result_dict['solution_type'] = result.find('nvt/solution').attrib['type'] 
                        result_dict['solution'] = result.find('nvt/solution').text 
                        cves = [] 
                        certs = [] 
                        other_links = [] 
                        for ref in result.xpath('nvt/refs/ref'): 
                            if ref.attrib['type'] == 'url': 
                                other_links.append(ref.attrib['id']) 
                            elif ref.attrib['type'] == 'cve': 
                                cves.append(ref.attrib['id']) 
                            elif ref.attrib['type'] == 'dfn-cert': 
                                certs.append(ref.attrib['id']) 
                        result_dict['CVEs'] = ', '.join(cves)
                        result_dict['CERTs'] = ', '.join(certs) 
                        result_dict['other_links'] = ', '.join(other_links)
                        result_dict['scan_type'] = self._scan_type 
                        result_dict['reinjected'] = False
                        result_dict['assumed_risk'] = False
                        result_dict['categories'] = []
                        for asset in assets:
                            if asset['asset_ip'] == result_dict['asset_ip']:
                                result_dict['categories'] = asset['categories']
                                result_dict['asset_name'] = asset['asset_name']
                                if result_dict['nvt_oid'] in asset['assumed_risks']:
                                    result_dict['assumed_risk'] = True
                        results.append(result_dict)

            df = pd.DataFrame(results)
            uniq_df = df.drop_duplicates(['vuln_name','asset_name','port'], keep='last')
            for index, row in uniq_df.iterrows():
                aux =  df.loc[(df['vuln_name'] == row['vuln_name']) & (df['asset_name'] == row['asset_name'])  & (df['port'] == row['port'])]
                if len(aux.index) > 1:
                    if ('gone' in aux['delta'].tolist() or 'same' in aux['delta'].tolist() or 'changed' in aux['delta'].tolist()) and 'new' in aux['delta'].tolist():
                        uniq_df['delta'][index] = 'same'
            results = uniq_df.to_dict('records')
        except GvmError as e: 
            print(e) 
            return False
        return report_dict, results, assets
    
    def fetch_report_info(self, report_id):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform() 
        report_dict = {} 
        results = []
        assets = []
        asset_ids = []
        try: 
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password) 
                finished = False
                fetched_results = []
                first = 1
                rows = 1000
                while not finished:
                    raw_xml = gmp.get_report(
                        report_id=report_id, 
                        filter_string=(f'apply_overrides=1 ignore_pagination=1 levels=hml min_qod=70 first={first} rows={rows} sort-reverse=severity notes=1 overrides=1')
                    )
                    fetched_results.extend(raw_xml.xpath('report/report/results/result'))  
                    if len(raw_xml.xpath('report/report/results/result')) == 1000:
                        first += rows
                    else:
                        finished = True
                for report in raw_xml.xpath('report'): 
                    report_dict = {} 
                    report_dict['report_id'] = report.attrib['id'] 
                    report_dict['timestamp'] = report.find('name').text 
                    if not report_dict['timestamp'].endswith('Z'):
                        report_dict['timestamp'] += 'Z'
                    report_dict['task_id'] = report.find('task').attrib['id'] 
                    report_dict['task_name'] = report.find('task/name').text 
                    report_dict['scan_status'] = report.find('report/scan_run_status').text
                    report_dict['reinjected'] = False

                for asset in raw_xml.xpath('report/report/host'):
                    asset_ids.append(asset.find('asset').attrib['asset_id']) 
                
                asset_ids = list(filter(None, asset_ids))

                assets = self.get_assets(asset_ids, report_id, report_dict['timestamp'])
                
                for result in fetched_results:
                    if result.find('name').text != 'Report outdated / end-of-life Scan Engine / Environment (local)':
                        result_dict = {} 
                        result_dict['delta'] = 'new' 
                        result_dict['report_id'] = report_id 
                        result_dict['vuln_name'] = result.find('name').text 
                        result_dict['vuln_id'] = result.attrib['id'] 
                        result_dict['timestamp'] = result.find('creation_time').text 
                        if not result_dict['timestamp'].endswith('Z'):
                            result_dict['timestamp'] += 'Z'
                        result_dict['asset_ip'] = result.find('host').text 
                        result_dict['asset_name'] = result.find('host/hostname').text 
                        if result_dict['asset_name'] is None:
                            result_dict['asset_name'] = result_dict['asset_ip']
                        result_dict['port'] = result.find('port').text 
                        result_dict['nvt_oid'] = result.find('nvt').attrib['oid'] 
                        result_dict['severity'] = result.find('threat').text 
                        result_dict['CVSS'] = float(result.find('severity').text) 
                        if result_dict['CVSS'] >= 9:
                            result_dict['severity'] = 'Critical'
                        nvt_info = result.find('nvt/tags').text
                        result_dict['summary'] = nvt_info.split('|')[1].split('=')[-1] 
                        result_dict['detection_result'] = result.find('description').text 
                        result_dict['insight'] = nvt_info.split('|')[2].split('=')[-1] 
                        result_dict['detection_method'] = nvt_info.split('|')[6].split('=')[-1]
                        result_dict['affected_software_os'] = nvt_info.split('|')[3].split('=')[-1] 
                        result_dict['impact'] = nvt_info.split('|')[4].split('=')[-1] 
                        result_dict['solution_type'] = result.find('nvt/solution').attrib['type'] 
                        result_dict['solution'] = result.find('nvt/solution').text 
                        cves = [] 
                        certs = [] 
                        other_links = [] 
                        for ref in result.xpath('nvt/refs/ref'): 
                            if ref.attrib['type'] == 'url': 
                                other_links.append(ref.attrib['id']) 
                            elif ref.attrib['type'] == 'cve': 
                                cves.append(ref.attrib['id']) 
                            elif ref.attrib['type'] == 'dfn-cert': 
                                certs.append(ref.attrib['id']) 
                        result_dict['CVEs'] = ', '.join(cves)
                        result_dict['CERTs'] = ', '.join(certs) 
                        result_dict['other_links'] = ', '.join(other_links)
                        result_dict['scan_type'] = self._scan_type 
                        result_dict['reinjected'] = False
                        result_dict['assumed_risk'] = False
                        result_dict['categories'] = {}
                        for asset in assets:
                            if asset['asset_ip'] == result_dict['asset_ip']:
                                result_dict['categories'] = asset['categories']
                                if result_dict['nvt_oid'] in asset['assumed_risks']:
                                    result_dict['assumed_risk'] = True
                        results.append(result_dict)
        except GvmError as e: 
            print(e) 
            return False
        return report_dict, results, assets
    
    def get_results(self, levels):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform() 
        results = []
        try: 
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password) 
                finished = False
                fetched_results = []
                first = 1
                rows = 1000
                while not finished:
                    raw_xml = gmp.get_results(
                        filter_string=(f'apply_overrides=1 min_qod=70 levels={levels} first={first} rows={rows} sort-reverse=severity')
                    )
                    fetched_results.extend(raw_xml.xpath('result'))  
                    if len(raw_xml.xpath('result')) == 1000:
                        first += rows
                    else:
                        finished = True
                
                for result in fetched_results: 
                    if result.find('name').text != 'Report outdated / end-of-life Scan Engine / Environment (local)':
                        result_dict = {} 
                        result_dict['delta'] = 'new' 
                        result_dict['vuln_name'] = result.find('name').text 
                        result_dict['vuln_id'] = result.attrib['id'] 
                        result_dict['timestamp'] = result.find('creation_time').text 
                        if not result_dict['timestamp'].endswith('Z'):
                            result_dict['timestamp'] += 'Z'
                        result_dict['asset_ip'] = result.find('host').text 
                        result_dict['asset_name'] = result.find('host/hostname').text 
                        if result_dict['asset_name'] is None:
                            result_dict['asset_name'] = result_dict['asset_ip']
                        result_dict['port'] = result.find('port').text 
                        result_dict['nvt_oid'] = result.find('nvt').attrib['oid'] 
                        result_dict['severity'] = result.find('threat').text 
                        result_dict['CVSS'] = float(result.find('severity').text) 
                        if result_dict['CVSS'] >= 9:
                            result_dict['severity'] = 'Critical'
                        nvt_info = result.find('nvt/tags').text
                        result_dict['summary'] = nvt_info.split('|')[1].split('=')[-1] 
                        result_dict['detection_result'] = result.find('description').text 
                        result_dict['insight'] = nvt_info.split('|')[2].split('=')[-1] 
                        result_dict['detection_method'] = nvt_info.split('|')[6].split('=')[-1]
                        result_dict['affected_software_os'] = nvt_info.split('|')[3].split('=')[-1] 
                        result_dict['impact'] = nvt_info.split('|')[4].split('=')[-1] 
                        result_dict['solution_type'] = result.find('nvt/solution').attrib['type'] 
                        result_dict['solution'] = result.find('nvt/solution').text 
                        cves = [] 
                        certs = [] 
                        other_links = [] 
                        for ref in result.xpath('nvt/refs/ref'): 
                            if ref.attrib['type'] == 'url': 
                                other_links.append(ref.attrib['id']) 
                            elif ref.attrib['type'] == 'cve': 
                                cves.append(ref.attrib['id']) 
                            elif ref.attrib['type'] == 'dfn-cert': 
                                certs.append(ref.attrib['id']) 
                        result_dict['CVEs'] = ', '.join(cves)
                        result_dict['CERTs'] = ', '.join(certs) 
                        result_dict['other_links'] = ', '.join(other_links)
                        result_dict['scan_type'] = self._scan_type 
                        result_dict['reinjected'] = False
                        result_dict['assumed_risk'] = False
                        results.append(result_dict)
        except GvmError as e: 
            print(e) 
            return False
        return results

    def get_assets(self, asset_ids, report_id, timestamp):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform() 
        assets = []
        try: 
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password) 
                for asset_id in asset_ids:
                    print(asset_id)
                    asset_xml = gmp.get_host(host_id = asset_id)
                    asset_dict = {}
                    assumed_risks = []
                    asset_dict['asset_id'] = asset_id
                    asset_dict['report_id'] = report_id
                    asset_dict['asset_ip'] = asset_xml.find('asset/name').text
                    asset_dict['asset_name'] = asset_xml.find('asset/name').text
                    asset_dict['asset_priority'] = 10
                    categories = []
                    for tag in asset_xml.xpath('asset/user_tags/tag'):
                        if tag.find('name').text.startswith('priority'):
                            try:
                                asset_dict['asset_priority'] = int(tag.find('value').text)
                            except Exception as e:
                                print("Error fetching asset priority")
                        elif tag.find('name').text.startswith('assumed'):
                            try:
                                assumed_risks.append(tag.find('value').text)
                            except Exception:
                                pass
                        elif tag.find('name').text.startswith('asset_id'):
                            try:
                                asset_dict['asset_id'] = tag.find('value').text
                            except Exception:
                                pass
                        elif tag.find('name').text.startswith('asset_name'):
                            try:
                                asset_dict['asset_name'] = tag.find('value').text
                            except Exception:
                                pass
                        else:
                            categories.append(tag.find('name').text)
                    for identifier in asset_xml.xpath('asset/identifiers/identifier'):
                        if identifier.find('source').attrib['id'] == report_id:
                            if identifier.find('name').text not in ['ip', 'hostname', 'ssh-key', 'MAC']:
                                if identifier.find('value').text.startswith("cpe:/"):
                                    categories.append(identifier.find('value').text.split(":")[2])
                                else:
                                    categories.append(identifier.find('value').text)
                            elif identifier.find('name').text == 'ip':
                                asset_dict['asset_ip'] = identifier.find('value').text
                            elif identifier.find('name').text == 'hostname':
                                asset_dict['asset_name'] = identifier.find('value').text
                    categories.append(self._scan_type)
                    categories = list(dict.fromkeys(categories))
                    asset_dict['categories'] = categories
                    asset_dict['assumed_risks'] = assumed_risks
                    asset_dict['timestamp'] = timestamp
                    asset_dict['scan_type'] = self._scan_type
                    asset_dict['reinjected'] = False
                    assets.append(asset_dict)
        except GvmError as e: 
            print(e) 
            print('error fetching assets')
            return False
        return assets

    def run_task(self, task_name):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password) 
                res = gmp.get_tasks(filter_string = 'name~' + task_name)
                task_id = res.xpath('task')[0].attrib['id']
                res = gmp.start_task(task_id=task_id)
                if res.attrib['status'] == '202':
                    return True
                else:
                    return False
        except GvmError as e:
            print(e)
        return False

    def delete_task(self, task_name):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password) 
                res = gmp.get_tasks(filter_string='name~' + task_name)
                task_id = res.xpath('task')[0].attrib['id']
                res = gmp.delete_task(task_id = task_id, ultimate = True)
                if res.attrib['status'] == '200':
                    return True
                else:
                    return False
        except GvmError as e:
            print(e)
        return False

    def check_status(self, task_name):
        scans = []
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password)  
                res = gmp.get_tasks(filter_string = 'rows=-1 name~' + task_name)
                for task in res.xpath('task'):
                    scan = {}
                    scan['name'] = task.find('name').text
                    scan['status'] = task.find('status').text
                    scan['progress'] = task.find('progress').text
                    if task.find('last_report/report'):
                        scan['last_report_id'] = task.find('last_report/report').attrib['id']
                        scan['last_report_timestamp'] = task.find('last_report/report/timestamp').text
                    scan['type'] = self._scan_type
                    scans.append(scan)
        except GvmError as e:
            print(e)
            return False
        return scans
      
    def create_tag(self, tag_name, value, ips):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password)
                tags_xml = gmp.get_tags(filter_string = ALL_ROWS)
                for tag in tags_xml.xpath('tag'):
                    if tag_name == tag.find('name').text and tag_name != 'asset_name':
                        return False 
                if len(ips) != 0:
                    ids = []
                    hosts_xml = gmp.get_hosts(filter_string = ALL_ROWS)
                    for host in hosts_xml.xpath('asset'):
                        if host.find('name').text in ips:
                            ids.append(host.attrib['id'])
                    gmp.create_tag(name = tag_name, resource_type = EntityType.HOST, value = value, resource_ids = ids) 
                else: 
                    gmp.create_tag(name = tag_name, resource_type = EntityType.HOST, value = value) 
        except GvmError as e:
            print(e)
            return False
        return True

    def delete_tag(self, tag_name):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password)
                tags_xml = gmp.get_tags(filter_string = tag_name)
                for tag in tags_xml.xpath('tag'):
                    tag_id = tag.attrib['id']
                gmp.delete_tag(tag_id = tag_id, ultimate = True) 
        except GvmError as e:
            print(e)
            return False
        return True
    
    def modify_tag_ips(self, tag_name, ips, action):
        connection = TLSConnection(hostname = self._host, port = self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                tag_id = ''
                gmp.authenticate(self._username, self._password)
                tags_xml = gmp.get_tags(filter_string = tag_name)
                for tag in tags_xml.xpath('tag'):
                    tag_id = tag.attrib['id']
                ids = []
                hosts_xml = gmp.get_hosts(filter_string = ALL_ROWS)
                for host in hosts_xml.xpath('asset'):
                    if host.find('name').text in ips:
                        ids.append(host.attrib['id'])
                if len(tag_id) > 0:
                    gmp.modify_tag(tag_id = tag_id, resource_action = action, resource_ids = ids) 
                else:
                    return False
        except GvmError as e:
            print(e)
            return False
        return True

    def modify_tag_value(self, tag_name, new_value):
        connection = TLSConnection(hostname=self._host, port=self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password)
                tags_xml = gmp.get_tags(filter_string = tag_name)
                for tag in tags_xml.xpath('tag'):
                    tag_id = tag.attrib['id']
                gmp.modify_tag(tag_id = tag_id, value = new_value) 
        except GvmError as e:
            print(e)
            return False
        return True
 
    def get_tags(self):
        tags = []
        connection = TLSConnection(hostname=self._host, port=self._port)
        transform = EtreeCheckCommandTransform()
        try:
            with Gmp(connection = connection, transform = transform) as gmp: 
                gmp.authenticate(self._username, self._password)
                tags_xml = gmp.get_tags(filter_string = 'rows=-1')
                for tag in tags_xml.xpath('tag'):
                    tag_dict = {}
                    if '-' in tag.find('name').text:
                        tag_dict['tag_name'] = tag.find('name').text.split('-')[1] 
                    else:
                        tag_dict['tag_name'] = tag.find('name').text
                    tag_dict['tag_value'] = tag.find('value').text
                    tag_dict['assigned_resources'] = tag.find('resources/count/total').text
                    tags.append(tag_dict)
        except GvmError as e:
            print(e)
            return False
        return tags
     