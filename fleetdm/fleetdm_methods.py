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

class FleetDMMethods():

    def __init__(self, fqdn:str, port: int, token:str) -> None:
        self.fqdn = fqdn
        self.port = port
        self.token = token
        self.headers = {'Authorization': 'Bearer {0}'.format(self.token)}
        self.url = "https://{0}:{1}/api/v1/fleet/".format(fqdn, port)

    def _get_host_count(self) -> None:
        try:
            url = self.url + "hosts/count"
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                logging.info("Total FleetDM managed hosts: {0}".format(req.json()['count']))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def _list_vulnerabilities(self) -> None:
        try:
            url = self.url + "/vulnerabilities"
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                for entry in req.json()['vulnerabilities']:
                    logging.info("CVE: {0} ; Affected Hosts: {1}".format(entry['cve'], entry['hosts_count']))
            else:
                logging.error("Failed to retrieve vulnerabilities")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    
