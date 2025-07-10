from datetime import datetime, timedelta, timezone
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

vault_session = VaultMethods()
vault_session.authenticate()
firewall_token = vault_session.retrieve_firewall_secret()

if firewall_token:
    logging.info("Retrieved firewall token")
else:
    logging.error("Failed to retrieve firewall token")