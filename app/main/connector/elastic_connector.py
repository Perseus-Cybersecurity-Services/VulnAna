from elasticsearch import Elasticsearch 

RED_STATUS_MESSAGE = 'Cluster status is RED. Information not sent'

class ElasticConnector:
    def __init__(
            self,
            _host,
            _port,
            _username,
            _password,
            _use_certs, 
            _cacert,
            _client_cert,
            _client_key
        ):
        self._host = _host
        self._port = _port
        self._username = _username
        self._password = _password
        self._use_certs = _use_certs
        self._cacert = _cacert
        self._client_cert = _client_cert
        self._client_key = _client_key

    def _create_instance(self):
        try:
            es = Elasticsearch(
                [f'https://{self._host}:{self._port}'],
                http_auth=(self._username,self._password),
                verify_certs=self._use_certs,
                ca_certs=self._cacert,
                client_cert=self._client_cert,
                client_key=self._client_key,
                ssl_show_warn=False
            )     
            return es
        except Exception as e:
            print(e)
            return False
    
    def check_connectivity(self):
        try:
            es = self._create_instance()
            if es.ping():
                return True
            else:
                print('Could not connect to elasticsearch.')
                return False
        except Exception as e:
            print(e) 
            print('Could not connect to elasticsearch.')
            return False

    def send_report(self, report, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                if not es.indices.exists(index = index_name): 
                    es.indices.create(index = index_name) 
                res = es.index(index = index_name, id = report['report_ids'][0], body = report) 
                if res['_shards']['successful'] < 1: 
                    print('Error ocurred trying to index report: ' + report['report_id']) 
                    return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def send_results(self, results, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                if not es.indices.exists(index = index_name): 
                    es.indices.create(index = index_name) 
                for result in results: 
                    res = es.index(index = index_name, id = result['vuln_id'], body = result) 
                    if res['_shards']['successful'] < 1: 
                        print('Error ocurred trying to index result: '+ result['vuln_id']) 
                        return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False
        
    def send_result(self, result, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                if not es.indices.exists(index = index_name): 
                    es.indices.create(index = index_name) 
                res = es.index(index = index_name, id = result['vuln_id'], body = result) 
                if res['_shards']['successful'] < 1: 
                    print('Error ocurred trying to index result: ' + result['vuln_id']) 
                    return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def send_asset(self, asset, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                if not es.indices.exists(index = index_name): 
                    es.indices.create(index = index_name) 
                res = es.index(index = index_name, id = asset['asset_id'] + '-' + asset['timestamp'].split('T')[0], body = asset) # Como muchos assets se repetirán a lo largo de los meses, se necesita concatenar la fecha para lograr un ID único
                if res['_shards']['successful'] < 1: 
                    print('Error ocurred trying to index asset: '+ asset['asset_id']) 
                    return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def send_assets(self, assets, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                if not es.indices.exists(index = index_name): 
                    es.indices.create(index = index_name) 
                for asset in assets: 
                    res = es.index(index = index_name, id = asset['asset_id'] + '-' + asset['timestamp'].split('T')[0], body = asset) # Como muchos assets se repetirán a lo largo de los meses, se necesita concatenar la fecha para lograr un ID único
                    if res['_shards']['successful'] < 1: 
                        print('Error ocurred trying to index asset: '+ asset['asset_id']) 
                        return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def get_report(self, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                if not es.indices.exists(index = index_name): 
                    es.indices.create(index = index_name) 
                res = es.search(
                    index=index_name, 
                    body={
                        'query': {
                            'match_all': {}
                        },
                        'sort': [
                            {
                                'timestamp': {
                                    'order': 'desc'
                                }
                            }
                        ],
                        'size': 1
                    }
                )
                if res['_shards']['successful'] < 1: 
                    print('Error ocurred trying to fetch report') 
                    return False 
                else:
                    report = res['hits']['hits'][0]['_source']
                    report.pop('top_vulns')
                    report.pop('scanned_assets')
                    return report
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def update_asset(self, asset, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                res = es.update(
                    index = index_name, 
                    id = asset['asset_id'] + '-' + asset['timestamp'].split('T')[0], # Como muchos assets se repetirán a lo largo de los meses, se necesita concatenar la fecha para lograr un ID único
                    body = {
                        'doc': {
                            'categories': asset['categories'],
                            'asset_score': asset['asset_score'],
                            'asset_priority': asset['asset_priority'],
                            'reinjected': True
                        }
                    }
                )
                if res['_shards']['successful'] < 1 and res['result'] != 'noop': 
                    print('An Error ocurred trying to update asset: '+ asset['asset_id']) 
                    return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def update_result(self, result, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red': 
                res = es.update(
                    index = index_name, 
                    id = result['vuln_id'],
                    body = {
                        'doc': {
                            'result_score': result['result_score'],
                            'reinjected': True
                        }
                    }
                ) 
                if res['_shards']['successful'] < 1 and res['result'] != 'noop':
                    print('An Error ocurred trying to update result: ' + result['vuln_id']) 
                    return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False

    def update_report(self, report, index_name): 
        try:
            es = self._create_instance()
            if es and es.cluster.health()['status'] != 'Red':  
                res = es.update(
                    index = index_name, 
                    id = report['report_ids'][0],
                    body = {
                        'doc': {
                            'top_vulns': report['top_vulns'],
                            'scanned_assets': report['scanned_assets'],
                            'reinjected': True
                        }
                    }
                ) 
                if res['_shards']['successful'] < 1 and res['result'] != 'noop': 
                    print('An Error ocurred trying to update report: ' + report['report_ids'][0]) 
                    return False 
                return True 
            else: 
                print(RED_STATUS_MESSAGE) 
            return False
        except Exception as e:
            print(e)
            return False
