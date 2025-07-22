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

    def __init__(self, addr:str, token:str) -> None:
        self.addr = addr
        self.port = port
        self.token = token
        self.hostname = ""
        # X-ApiKeys: accessKey=ACCESS_KEY; secretKey=SECRET_KEY;
        self.headers = {'Authorization': 'Bearer {}'.format(self.token)}
        # Keeping the headers here for future firmware releases
        self.url = "https://{0}:{1}/api/v2/".format(addr, port)