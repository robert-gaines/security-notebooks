from datetime import datetime, timedelta, timezone
from requests.adapters import HTTPAdapter
from IPython.display import display
from urllib3.util import Retry
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

        self.session = requests.Session()
        retry_configuration = Retry(
            total=5,
            backoff_factor=.1,
            allowed_methods={'GET'},
            status_forcelist=[429]
        )

        self.session.mount('https://', HTTPAdapter(
            max_retries=retry_configuration))

    def _gen_export_file_name(self, str_pfx: str, fmt: str) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = str_pfx + timestamp + fmt
        return filename

    def _query_nvd_data(self, cve:str, nist_nvd_token:str) -> float:
        try:
            logging.info("Sending query for CVE: {0}".format(cve))
            headers = {'apiKey':nist_nvd_token}
            url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={0}".format(cve)
            req = self.session.get(url=url, headers=headers)
            if req.status_code == 200:
                for entry in req.json()['vulnerabilities']:
                    cve_data = entry['cve']
                    if cve_data['vulnStatus'] != 'Awaiting Analysis':
                        tmp_dct = {
                            'Description': cve_data['descriptions'][0]['value'],
                            'CVSS Version': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['version'],
                            'CVSS Base Score': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'],
                            'CVSS Base Severity': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['baseSeverity'],
                            'Attack Complexity': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['attackComplexity'],
                            'Attack Vector': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['attackVector'],
                            'Privileges Required': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['privilegesRequired'],
                            'User Interaction': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['userInteraction'],
                            'Scope': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['scope'],
                            'Confidentiality Impact': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['confidentialityImpact'],
                            'Integrity Impact': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['integrityImpact'],
                            'Availability Impact': cve_data['metrics']['cvssMetricV31'][0]['cvssData']['availabilityImpact'],
                            'Exploitability Score': cve_data['metrics']['cvssMetricV31'][0]['exploitabilityScore'],
                            'Impact Score': cve_data['metrics']['cvssMetricV31'][0]['impactScore']
                        }
                        return tmp_dct
                    else:
                        return None
            else:
                logging.error("No data returned for CVE: {0} - {1}".format(cve, req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
        
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

    def _get_hosts(self) -> None:
        try:
            url = self.url + "hosts"
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                hosts = req.json()['hosts']
                for host in hosts:
                    logging.info("{0} : {1} : {2} : {3}".format(host['hostname'],
                                                                host['platform'],
                                                                host['os_version'],
                                                                host['code_name']))
                df = pd.DataFrame(hosts)
                filename = self._gen_export_file_name('fleetdm_hosts_', '.xlsx')
                df.to_excel(filename, index=False)
            else:
                logging.error("Failed to retrieve hosts: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def _get_host_vulnerabilities(self, nist_nvd_token: str) -> None:
        vulnerable_packages = []
        hosts = []
        try:
            url = self.url + "hosts?populate_software=true"
            req = requests.get(url=url, headers=self.headers, verify=False)
            if req.status_code == 200:
                for entry in req.json()['hosts']:
                    hosts.append(entry['computer_name'])
                    logging.info("Processing FleetDM Host: {0}".format(entry['computer_name']))
                    for package in entry['software']:
                        if(package['vulnerabilities'] is not None):
                            host_dct = {'hostname':entry['computer_name']}
                            for vulnerability in package['vulnerabilities']:
                                temp_dct = {**host_dct, **package}
                                del temp_dct['vulnerabilities']
                                vuln_dct = {**temp_dct, **vulnerability}
                                nvd_data = {}
                                if 'cve' in vuln_dct.keys():
                                    nvd_data = self._query_nvd_data(vuln_dct['cve'], nist_nvd_token)
                                if nvd_data is not None:
                                    vuln_dct = {**vuln_dct, **nvd_data}
                                    vulnerable_packages.append(vuln_dct)
                                    time.sleep(5)
                                else:
                                    vulnerable_packages.append(vuln_dct)
                for package in vulnerable_packages:
                    logging.info(package)
                    logging.info('\n')
                df = pd.DataFrame(vulnerable_packages)
                filename = self._gen_export_file_name('fleetdm_vulnerabilities_', '.xlsx')
                df.to_excel(filename, index=False)
            else:
                logging.error("Failed to retrieve hosts: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
            

    
