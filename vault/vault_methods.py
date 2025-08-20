from getpass import getpass
import requests
import urllib3
import logging

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

class VaultMethods():

    def __init__(self) -> None:
        self.fqdn = input("Enter the Vault FQDN-> ")
        self.username = input("Enter the Vault username-> ")
        self.password = getpass("Enter the Vault password-> ")
        self.token = ""
        self.headers = ""
        self.url = "https://{0}".format(self.fqdn)

    def authenticate(self):
        """ Authenticate to vault with supplied credentials """
        try:
            payload = { "password" : self.password }
            url = "https://{0}/v1/auth/ldap/login/{1}".format(self.fqdn, self.username)
            response = requests.post(url=url, json=payload, verify=False)
            if response.json()['auth']['client_token']:
                self.token = response.json()['auth']['client_token']
                self.headers = { 'X-Vault-Token': self.token }
            else:
                logging.info("Failed to retrieve token")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def retrieve_iris_secret(self) -> str:
        '''Retrieve DFIR IRIS API token'''
        url = self.url + "/v1/iris/data/iris-service-token"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()['data']['data']['token']
            return response
        except Exception as e:
            logging.exception(f"Error retrieving DFIR Iris secret: {e}")
            return None
    
    def retrieve_gravwell_secret(self) -> str:
        '''Retrieve Gravwell API token'''
        url = self.url + "/v1/gravwell/data/gravwell-service-token"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()['data']['data']['token']
            return response
        except Exception as e:
            logging.exception(f"Error retrieving Gravwell secret: {e}")
            return None

    def retrieve_firewall_secret(self) -> str:
        ''' Retrieve the firewall API token '''
        url = self.url + "/v1/fortinet/data/fortigate-automation"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()['data']['data']['key']
            return response
        except Exception as e:
            logging.exception(f"Error retrieving firewall secret: {e}")
            return None

    def retrieve_misp_secret(self) -> str:
        ''' Retrieve the MISP token '''
        url = self.url + "/v1/misp/data/misp-api"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()['data']['data']['key']
            return response
        except Exception as e:
            logging.exception(f"Error retrieving MISP secret: {e}")
            return None

    def retrieve_fleetdm_secret(self) -> str:
        ''' Retrieve the FleetDM token '''
        url = self.url + "/v1/fleetdm/data/fleetdm-api-token"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()['data']['data']['key']
            return response
        except Exception as e:
            logging.exception(f"Error retrieving FleetDM secret: {e}")
            return None

    def retrieve_nist_nvd_secret(self) -> str:
        ''' Retrieve the NIST NVD token '''
        url = self.url + "/v1/NIST/data/NVD-API"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()['data']['data']['token']
            return response
        except Exception as e:
            logging.exception(f"Error retrieving NIST NVD secret: {e}")
            return None

    def retrieve_elastic_secret(self) -> str:
        ''' Retrieve the Elastic API token '''
        url = self.url + "/v1/elastic/data/elastic-api-token"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            response = response.json()
            token = response['data']['data']['token']
            return token
        except Exception as e:
            logging.exception(f"Error retrieving Elastic secret: {e}")
            return None

    def retrieve_nessus_secrets(self) -> list:
        ''' Retrieve the Nessus Secrets '''
        url = self.url + "/v1/nessus/data/nessus-api-keys"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            access = response.json()['data']['data']['access']
            secret = response.json()['data']['data']['secret']
            return [access, secret]
        except Exception as e:
            logging.exception(f"Exception raised while retrieving Nessus secrets: {e}")
            return None

    def retrieve_proxmox_secrets(self) -> str:
        ''' Retrieve the Proxmox Secrets '''
        url = self.url + "/v1/proxmox/data/security-automation"
        try:
            response = requests.get(url, headers=self.headers, verify=False)
            if response.status_code == 200:
                data = response.json()['data']['data']
                identity = data['identity']
                realm = data['realm']
                role = data['role']
                token = data['token']
                return {'identity': identity,
                        'realm': realm,
                        'role': role,
                        'token': token}
            else:
                logging.info("Failed to retrieve Proxmox authentication data")
        except Exception as e:
            logging.exception(f"Exception raised while retrieving Proxmox: {e}")
            return None
        