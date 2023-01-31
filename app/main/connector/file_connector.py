import os
from ..config.app_config import BASEDIR

def get_processed_reports(user):
    saved_reports = []
    try: 
        f = open(BASEDIR + '/files/' + user + '/report_ids.txt', 'r') 
        for x in f: 
            saved_reports.append(x.rstrip()) 
        f.close()
    except Exception as e:
        print(e) 
        print('Error checking previously saved reports') 
    return saved_reports  

def save_report_id(user, ids):
    try: 
        file = BASEDIR + '/files/' + user + '/report_ids.txt'
        parent_dir = os.path.dirname(file)
        if not os.path.exists(parent_dir):
            os.makedirs(parent_dir)
        with open(file, 'a') as f:
            for id in ids:
                f.write(id + '\n') 
    except Exception as e: 
        print('Error saving report_id: ' + id)  
        print(e)  