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

    def get_scans(self) -> None:
        try:
            url = self.url + 'scans'
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                if 'scans' in req.json().keys():
                    for scan in req.json()['scans']:
                        for item in scan.keys():
                            logging.info("{0} :{1}".format(item, scan[item]))
            else:
                logging.error("Failed to retrieve scans: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
            