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

class ElasticMethods():

    def __init__(self, fqdn:str, key: str):
        self.headers = { "Authorization": f"ApiKey {key}",
                         "Content-Type": "application/json"}
        self.url = "https://{0}/api/".format(fqdn)

    def _gen_export_file_name(self, str_pfx: str, fmt: str) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = str_pfx + timestamp + fmt
        return filename
    
    def _get_agents(self) -> None:
        ''' Retrieve Elastic Agents '''
        try:
            url = self.url + 'fleet/agents?perPage=100'
            req = requests.get(url=url, headers=self.headers, verify=False)
            df = pd.DataFrame(req.json()['items'])
            filename = self._gen_export_file_name('elastic_agents_', '.xlsx')
            display(df)
            df.to_excel(filename, index=False)
        except Exception as e:
            logging.error("Exception raised: {0}".format(e))