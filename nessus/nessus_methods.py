from datetime import datetime, timedelta, timezone
from IPython.display import display
import pandas as pd
import requests
import logging
import urllib3
import time
import sys
import os
sys.path.append(os.path.abspath('../vault'))
from vault_methods import VaultMethods

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

class NessusMethods():

    def __init__(self, fqdn:str, access_key:str, secret_key:str) -> None:
        self.fqdn = fqdn
        self.headers = {'X-ApiKeys': 'accessKey={0}; secretKey={1}'.format(
            access_key,secret_key)}
        self.url = "https://{0}/".format(fqdn)

    def gen_export_file_name(self, str_pfx: str, fmt: str) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = str_pfx + timestamp + fmt
        return filename
    
    def get_server_status(self) -> None:
        try:
            url = self.url + 'server/status'
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                logging.info(req.headers)
                for entry in req.json().keys():
                    logging.info("{0} : {1}".format(entry, req.json()[entry]))
                logging.info("")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def get_plugin_details(self, plugin_id: str) -> None:
        try:
            url = self.url + '/plugins/plugin/{0}'.format(plugin_id)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                tmp_dct = {}
                for attribute in req.json()['attributes']:
                    tmp_dct[attribute['attribute_name']] = attribute['attribute_value']
                return tmp_dct
            else:
                return None
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
    
    def get_scans(self) -> dict:
        scans = {}
        try:
            url = self.url + 'scans'
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                if 'scans' in req.json().keys():
                    for scan in req.json()['scans']:
                        scans[scan['id']] = scan['name']
                        logging.info("Located scan: {0} : {1}".format(scan['id'],
                                                                      scan['name']))
                        # for item in scan:
                        #     logging.info("{0} : {1}".format(item, scan[item]))
                return scans
            else:
                logging.error("Failed to retrieve scans: {0}".format(req.status_code))
                return None
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def get_scan_results(self, scans: dict) -> None:
        results = []
        try:
            for key in scans.keys():
                logging.info("Processing: {0}".format(scans[key]))
                url = self.url + "scans/{0}".format(key)
                req = requests.get(url=url, headers=self.headers, verify=False)
                if req.status_code == 200:
                    for element in req.json()['vulnerabilities']:
                        plugin_data = self.get_plugin_details(element['plugin_id'])
                        record = {}
                        record['scan_name'] = scans[key]
                        record = {
                            **element,
                            **plugin_data
                        }
                        results.append(record)
            df = pd.DataFrame(results)
            filename = self.gen_export_file_name('nessus_vuln_scan_results_', '.xlsx')
            df.to_excel(filename, index=False)
            logging.info("Exported results to: {0}".format(filename))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
            