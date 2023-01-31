import json

from ..config.app_config import BASEDIR

class Scorer: 

    def __init__(
        self,
        user,
        assets,
        results,
        reports
        ):
        self._user = user
        self._assets = assets
        self._results = results
        self._reports = reports
        self._categories = self.get_categories()
        
    def __assign_multiplier(self):
        category_names = []
        for category in self._categories:
            category_names.append(category["category_name"].lower())
        for asset in self._assets:
            asset['multiplier'] = 0
            for category in asset['categories']:
                if category.lower() not in category_names:
                    print('Warning: '+category+' category is not in categories.json. Remember to add it, by default multiplier is not applied')
                else:
                    for cat in self._categories:
                        if cat['category_name'].lower() == category.lower():
                            asset['multiplier'] += cat['multiplier']
                if asset['multiplier'] > 1000:
                    asset['multiplier'] = 1000
    
    def __unassign_multiplier(self):
        for asset in self._assets:
            asset.pop('multiplier')
    
    def __calculate_single_scores(self):
        self._result_names = []
        for asset in self._assets:
            asset['asset_score'] = 0
            asset['asset_virtual_score'] = 0
        for result in self._results:
            if result['vuln_name'] not in self._result_names:
                self._result_names.append(result['vuln_name'])
            for asset in self._assets:
                if result['delta'] == 'gone':
                    result['result_score'] = 0
                    result['result_virtual_score'] = 0
                elif result['asset_ip'] == asset['asset_ip']:
                    if not result['assumed_risk']:
                        result['result_score'] = asset['multiplier'] + (result['CVSS'] * 10 * asset['asset_priority'])
                        if result['result_score'] > 1000:
                            result['result_score'] = 1000
                        if result['result_score'] > asset['asset_score']:
                            asset['asset_score'] = result['result_score']
                    else:
                        result['result_score'] = 0
                    result['result_virtual_score'] = asset['multiplier'] + (result['CVSS'] * 10 * asset['asset_priority'])
                    if result['result_virtual_score'] > 1000:
                        result['result_virtual_score'] = 1000
                    if result['result_virtual_score'] > asset['asset_virtual_score']:
                        asset['asset_virtual_score'] = result['result_virtual_score']
    
    def __calculate_group_scores(self):
        for category in self._reports['scanned_assets']:
            category['score'] = 0
            category['virtual_score'] = 0
            for asset in self._assets:
                if category['category_name'] == 'global':
                    category['score'] += asset['asset_score']
                    category['virtual_score'] += asset['asset_virtual_score']
                if category["category_name"] in asset["categories"]:
                    category['score'] += asset['asset_score']
                    category['virtual_score'] += asset['asset_virtual_score']
            try:
                category['score'] = round(category['score']/category['amount'])
                category['virtual_score'] = round(category['virtual_score']/category['amount'])
            except Exception:
                print('Error calculating scores')

    def __calculate_top_vulnerabilities(self):
        top_vulns = []
        for vulnarability in self._result_names:
            vuln_dict = {}
            vuln_dict['appearances'] = 0
            vuln_dict['new_score'] = 0
            for asset in self._assets:
                asset_score = 0
                for result in self._results:
                    if result['vuln_name'] == vulnarability and result['asset_ip'] == asset['asset_ip'] and not result['assumed_risk'] and result['delta'] != 'gone' :
                        vuln_dict['appearances'] +=1
                    if result['vuln_name'] != vulnarability and result['asset_ip'] == asset['asset_ip'] and not result['assumed_risk'] and result['delta'] != 'gone':
                        if 'result_score' in result.keys() and result['result_score'] > asset_score: 
                            asset_score = result['result_score'] 
                vuln_dict['new_score'] += asset_score
            vuln_dict['vuln_name'] = vulnarability
            
            vuln_dict['new_score'] = round(vuln_dict['new_score']/len(self._assets),2)
            top_vulns.append(vuln_dict)
        self._reports['top_vulns'] = top_vulns
            
    def get_categories(self):
        categories = []
        with open(BASEDIR + '/files/categories.json','r') as outfile: 
            categories.extend(json.load(outfile)) 
        return categories

    def run(self):
        self.__assign_multiplier()
        self.__calculate_single_scores()
        self.__calculate_group_scores()
        self.__calculate_top_vulnerabilities()
        self.__unassign_multiplier()
        return self._assets, self._results, self._reports