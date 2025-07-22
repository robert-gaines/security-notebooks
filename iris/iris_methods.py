import requests
import urllib3
import logging
import json

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    level=logging.INFO)

class IrisMethods():

    def __init__(self, fqdn: str, key: str):
        self.key = key
        self.fqdn = fqdn
        self.url = "https://{0}/".format(self.fqdn)
        self.headers = {
            'Content-Type':'application/json',
            'Authorization':'Bearer {0}'.format(self.key)
        }
        self.cases = []
        self.alerts = []
        self.owner_id = "1"
        self.open_cases = []

    def retrieve_open_cases(self) -> None:
        url = self.url + "manage/cases/list"
        try:
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                raw_case_data = req.json()['data']
                logging.info("Retrieved: {0} cases".format(len(raw_case_data)))
                for case in raw_case_data:
                    if case['state_name'] == 'Open':
                        # logging.info("Located: {0}".format(case['case_name']))
                        self.open_cases.append(case['case_id'])
                logging.info("Identified {0} open cases in IRIS".format(len(self.open_cases)))
            else:
                logging.error("Failed to retrieve cases")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def close_open_cases(self) -> None:
        if self.open_cases:
            for case in self.open_cases:
                case_payload = {
                    "owner_id": self.owner_id
                }
                try:
                    response = requests.post(url="https://{0}/manage/cases/close/{1}".format(self.fqdn,case),
                                             headers=self.headers,
                                             data=json.dumps(case_payload),
                                             verify=False)
                    if response.status_code == 200:
                        logging.info("Successfully closed: {0}".format(case))
                    else:
                        logging.info("Failed to close case: {0}".format(case))
                except Exception as e:
                    logging.exception("Exception raised closing case: {0}".format(e))
        else:
            logging.error("No open cases in the queue")