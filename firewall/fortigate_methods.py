from datetime import datetime, timedelta, timezone
from IPython.display import display
import pandas as pd
import requests
import logging
import urllib3
import sys
import os
sys.path.append(os.path.abspath('../vault'))
from vault_methods import VaultMethods

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

class FortigateMethods():

    def __init__(self, addr:str, port:int, token:str) -> None:
        self.addr = addr
        self.port = port
        self.token = token
        self.headers = {'Authorization': 'Bearer {}'.format(self.token)}
        # Keeping the headers here for future firmware releases
        self.url = "https://{0}:{1}/api/v2/".format(addr, port)

    def check_token_validity(self) -> bool:
        # Check the API token's validity
        logging.info("Checking the firewall API token's validity")
        try:
            url = self.url + "monitor/system/status?access_token={0}".format(self.token)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                logging.info("Valid token")
                logging.info("Appliance status: {0}".format(req.json()['status']))
                logging.info("Established contact with: {0}".format(req.json()['serial']))
                return True
            else:
                logging.error("Invalid token or request: {0}".format(req.status_code))
                return False
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def retrieve_arp_cache(self) -> None:
        # Retrieve the ARP Cache
        logging.info("Requesting ARP cache data")
        try:
            url = self.url + "monitor/network/arp?access_token={0}".format(self.token)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200 and 'results' in req.json().keys(): 
                df = pd.DataFrame(req.json()['results'])
                display(df)
            else:
                logging.error("Failed to retrieve ARP cache data: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def retrieve_wireless_clients(self) -> None:
        # Retrieve wireless client data
        logging.info("Requesting wireless client data")
        try:
            url = self.url + "monitor/wifi/client?access_token={0}".format(self.token)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200 and 'results' in req.json().keys():
                df = pd.DataFrame(req.json()['results'])
                display(df)
            else:
                logging.error("Failed to retrieve wireless client data: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def retrieve_session_table(self) -> None:
        # Retrieve session table data
        logging.info("Requesting session table data")
        try:
            # Session count is capped at 1000 per the API specifications
            url = self.url + "monitor/firewall/session?access_token={0}&count=1000".format(self.token)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200 and 'results' in req.json().keys():
                df = pd.DataFrame(req.json()['results']['details'])
                display(df)
                df.to_excel("firewall_session_table.xlsx", index=False)
            else:
                logging.error("Failed to retrieve session table data: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def retrieve_switchport_devices(self) -> None:
        # Retrieve a list of all devices that are connected to switchports
        logging.info("Requesting switchport device data")
        try:
            url = self.url + "monitor/switch-controller/detected-device?access_token={0}".format(self.token)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200 and 'results' in req.json().keys():
                df = pd.DataFrame(req.json()['results'])
                display(df)
                df.to_excel("switchport_devices.xlsx", index=False)
            else:
                logging.error("Failed to retrieve switchport device data: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
        