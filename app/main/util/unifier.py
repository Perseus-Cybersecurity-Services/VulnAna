from time import strptime, strftime

def unify_lists(*lists):
    unified_lists = []
    for list in lists:
        unified_lists.extend(list)
    return unified_lists

def process_reports(assets, reports):
    unified_reports = {}
    report_ids = [] 
    task_ids = [] 
    task_names = []
    timestamps = []
    high = 0
    medium = 0
    low = 0
    vuln_count = 0

    if isinstance(reports, list):
        for report in reports:
            report_ids.append(report['report_id'])
            task_ids.append(report['task_id'])
            task_names.append(report['task_name'])
            timestamps.append(strftime('%Y-%m-%dT%H:%M:%SZ', strptime(report['timestamp'],'%Y-%m-%dT%H:%M:%SZ')))
        unified_reports['report_ids'] = report_ids
        unified_reports['task_ids'] = task_ids
        unified_reports['task_names'] = task_names
        unified_reports['timestamp'] = max(timestamps)
    else:
        unified_reports['report_ids'] = reports['report_ids']
        unified_reports['task_ids'] = reports['task_ids']
        unified_reports['task_names'] = reports['task_names']
        unified_reports['timestamp'] = reports['timestamp']

    unified_reports['scanned_assets'] = []
    categories = []
    for asset in assets:
        for category in asset['categories']:
            categories.append(category)
    assets_count = dict((x,categories.count(x)) for x in set(categories))
    assets_count['global'] = len(assets)
    for asset in assets_count:
        asset_count_dict = {}
        asset_count_dict['category_name'] = asset
        asset_count_dict['amount'] = assets_count[asset]
        unified_reports['scanned_assets'].append(asset_count_dict) 
        unified_reports['scanned_assets'].reverse()
    return unified_reports

def organize_reports(reports): 
    reports_dict = {}
    for report in reports:
        date_key = report['timestamp'].split('-')[0]+'-'+report['timestamp'].split('-')[1]
        if date_key not in reports_dict:
            reports_dict[date_key] = []
        reports_dict[date_key].append(report['report_id'])
    return reports_dict


