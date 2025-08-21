import pandas as pd
import requests
import logging
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

class MISPMethods():

    def __init__(self, token: str, fqdn: str):
        self.headers = {
            'Accept': 'application/json',
            'Authorization': token
        }
        self.url = "https://{0}/".format(fqdn)

    def search_events(self, address: str):
        url = self.url + 'events/restSearch/json?limit=1'
        payload = {
            'value':address
        }
        try:
            req = requests.post(url=url,
                                headers=self.headers,
                                json=payload,
                                verify=False)
            if req.status_code == 200:
                response = req.json()['response']
                if response:
                    results = response[0]['Event']['Attribute']
                    filename = address + ".csv"
                    df = pd.DataFrame(results)
                    df.to_csv(filename, index=False)
                    logging.info("MISP Event data saved in: {0}".format(filename))
            else:
                logging.info("Failed to identify any MISP records")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
        