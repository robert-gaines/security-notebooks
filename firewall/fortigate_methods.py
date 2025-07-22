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

class FortigateMethods():

    def __init__(self, addr:str, port:int, token:str) -> None:
        self.addr = addr
        self.port = port
        self.token = token
        self.hostname = ""
        self.headers = {'Authorization': 'Bearer {}'.format(self.token)}
        # Keeping the headers here for future firmware releases
        self.url = "https://{0}:{1}/api/v2/".format(addr, port)

    def gen_config_file_name(self) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = self.hostname+"_"+timestamp+'.conf'
        return filename

    def gen_export_file_name(self, str_pfx: str, fmt: str) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = str_pfx + timestamp + fmt
        return filename
    
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
                if 'hostname' in req.json()['results'].keys():
                    self.hostname = req.json()['results']['hostname']
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
                filename = self.gen_export_file_name('arp_cache_', '.xlsx')
                display(df)
                df.to_excel(filename, index=False)
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
                filename = self.gen_export_file_name('wireless_clients_', '.xlsx')
                display(df)
                df.to_excel(filename, index=False)
            else:
                logging.error("Failed to retrieve wireless client data: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def disassociate_wireless_client(self, mac: str) -> None:
        # Disassociate wireless client from AP
        logging.info("Sending disassociate command to the wireless controller")
        logging.info("Attempting to remove: {0}".format(mac))
        try:
            payload = { 'mac': mac }
            url = self.url + "monitor/wifi/client/disassociate?access_token={0}".format(self.token)
            req = requests.post(url=url, headers=self.headers, json=payload, verify=False)
            if req.status_code == 200:
                logging.info("Successfully disassociated the client: {0}".format(mac))
            else:
                logging.error("Failed to disassociate wireless client: {0}".format(req.status_code))
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
                filename = self.gen_export_file_name('session_table_', '.xlsx')
                df.to_excel(filename, index=False)
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
                filename = self.gen_export_file_name('switchport_devices_', '.xlsx')
                df.to_excel(filename, index=False)
            else:
                logging.error("Failed to retrieve switchport device data: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def backup_configuration(self) -> None:
        conf_filename = self.gen_config_file_name()
        configuration_url = self.url + "monitor/system/config/backup/?scope=global&amp;access_token={0}".format(self.token)
        configuration_request = requests.get(configuration_url, headers=self.headers, timeout=3, verify=False) 
        if configuration_request.status_code == 200:
            logging.info("Successfully retrieved the configuration data")
            config_data = configuration_request.text
            with open(conf_filename,'w') as configuration_file:
                configuration_file.write(config_data)
        else:
            logging.error("Failed to retrieve device configuration data")

    def list_sdwan_zones(self) -> None:
        zone_list = []
        url = self.url + "cmdb/system/sdwan?access_token={0}".format(self.token)
        response = requests.get(url,headers=self.headers,verify=False)
        if(response.status_code == 200):
            zones = response.json()
            zones = zones['results']['zone']
            for interface in zones:
                zone_list.append(interface['name'])
            logging.info("Identified {0} SDWAN zones".format(len(zone_list)))
            return zone_list
        else:
            return zone_list
    
    def list_zones(self) -> None:
        zone_list = []
        url = self.url + "cmdb/system/zone?access_token={0}".format(self.token)
        response = requests.get(url,headers=self.headers,verify=False)
        if(response.status_code == 200):
            zones = response.json()
            zones = zones['results']
            for interface in zones:
                zone_list.append(interface['name'])
            logging.info("Identified {0} zones".format(len(zone_list)))
            return zone_list
        else:
            return zone_list

    def list_interfaces(self) -> None:
        interface_list = []
        url = self.url + "cmdb/system/interface?access_token={0}".format(self.token)
        response = requests.get(url, headers=self.headers, verify=False)
        if response.status_code == 200:
            interfaces = response.json()
            interfaces = interfaces['results']
            for interface in interfaces:
                interface_list.append(interface['name'])
            logging.info("Identified {0} interfaces".format(len(interface_list)))
            return interface_list
        else:
            return interface_list

    def create_address_object(self, address: str) -> None:
        obj_name = "Automation_"+"[BLOCK]"+"_"+address
        logging.info("Attempting to create: {0}".format(obj_name))
        subnet = address+"/32"
        json = {
                    'name'  :obj_name,
                    'subnet':subnet,
                    'type'  :'ipmask',
               }
        url = self.url + "cmdb/firewall/address?access_token={0}".format(self.token)
        response = requests.post(url, headers=self.headers, json=json, verify=False)
        if response.status_code == 200:
            logging.info("Sucessfully created the address object: {0} ".format(obj_name))
            return obj_name
        else:
            logging.error("Failed to create the address object ")
            return None

    def create_policy(self, srcintf: str, dstintf: str, obj_name: str) -> None:
        ts = time.ctime()
        ts = ts.replace(' ','_')
        ts = ts.replace(':','_')
        pol_name = "Deny - {0}:{1}".format(obj_name, ts)
        json = {
                    'status'  : 'enable',
                    'name'    : pol_name,
                    'srcintf' : [ {'name': srcintf }  ],
                    'dstintf' : [ {'name': dstintf }  ],
                    'srcaddr' : [ {'name': 'all'}      ],
                    'dstaddr' : [ {'name': obj_name}   ],
                    'service' : [ {'name': 'ALL'}      ],
                    'schedule': 'always',
                    'action'  : 'deny',
                }
        url = self.url + "cmdb/firewall/policy?access_token={0}".format(self.token)
        response = requests.post(url, headers=self.headers, json=json, verify=False)
        if response.status_code == 200:
            logging.info("Sucessfully created a deny policy with the following name: {0} ".format(pol_name))
        else:
            logging.error("Failed to create the deny policy ")

    

    
    

    
        