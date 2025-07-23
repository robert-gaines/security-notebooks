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
                        logging.info("Located: {0} -> {1}".format(case['case_id'],
                                                                  case['case_name']))
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

    def create_notes_directory(self, case_id, directory_name) -> str:
        """ Creates a note directory for case notes """
        try:
            payload = { "cid": case_id, "name": str(directory_name) }
            url = self.url + "case/notes/directories/add"
            response = requests.post(url=url,
                                     headers=self.headers,
                                     data=json.dumps(payload),
                                     verify=False)
            if response.status_code == 200:
                return response.json()['data']['id']
            else:
                return None
        except Exception as e:
            return None

    def export_case_to_json(self, case_id: str) -> str:
        try:
            url = self.url + "case/export?cid={0}".format(case_id)
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                logging.info("Retrieved case data for  {0}".format(case_id))
                case_data = req.json()
                filename = "case_{0}.json".format(case_id)
                with open(filename, "w") as file:
                    json.dump(case_data, file, indent=1)
                logging.info("Case exported to JSON: {0}".format(filename))
            else:
                logging.error("Failed to retrieve case data")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
                
    def add_case_note(self,
                      case_id,
                      dir_id,
                      note_title,
                      note) -> bool:
        """ Add a note to a DFIR IRIS case directory """
        try:
            payload = { "cid": case_id, 
                        "note_title": str(note_title),
                        "note_content": str(note),
                        "directory_id": dir_id }
            response = requests.post(url="https://{0}/case/notes/add".format(self.cms),
                                     headers=self.cms_headers,
                                     data=json.dumps(payload),
                                     verify=False)
            if response.status_code == 200:
                return True
            else:
                return False
        except Exception as e:
            return False

    def get_case_iocs(self, case_id) -> None:
        try:
            url = self.url + "case/ioc/list?cid={0}".format(case_id)
            response = requests.get(url=url,
                                    headers=self.headers,
                                    verify=False)
            iocs = response.json()['data']
            for ioc in iocs['ioc']:
                logging.info(ioc['ioc_value'])
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))