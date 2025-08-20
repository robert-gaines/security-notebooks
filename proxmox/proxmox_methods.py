from datetime import datetime
import requests
import logging
import urllib3
import time
import sys
import os

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

class ProxmoxMethods():

    def __init__(self, fqdn: str, identity: str, realm:str, role: str, token: str) -> None:
        self.fqdn = fqdn
        self.identity = identity
        self.realm = realm
        self.token = token
        self.role = role
        self.headers = {
            'Authorization': "PVEAPIToken={0}@{1}!{2}={3}".format(self.identity,
                                                                  self.realm,
                                                                  self.role,
                                                                  self.token)
        }
        self.url = "https://{0}:8006/api2/json/".format(self.fqdn)
        self.nodes = []
        self.hosts = {}

    def _get_nodes(self) -> None:
        url = self.url + 'nodes'
        req = requests.get(url=url, headers=self.headers, verify=False)
        if req.status_code == 200:
            for node in req.json()['data']:
                logging.info("Node: {0} : Status: {1}".format(node['id'],node['status']))
                self.nodes.append(node['id'])
        else:
            logging.error("Failed to retrieve nodes")

    def _get_hosts(self) -> None:
        if self.nodes:
            for node in self.nodes:
                node = node.split('/')[1]
                url = self.url + "nodes/{0}/qemu".format(node)
                req = requests.get(url=url, headers=self.headers, verify=False)
                logging.info("Node: {0}".format(node))
                if req.status_code == 200:
                    data = req.json()['data']
                    for entry in data:
                        logging.info("Host: {0} : VMID: {1}".format(entry['name'],
                                                                    entry['vmid']))
                        self.hosts[entry['vmid']] = entry['name']
                else:
                    logging.error("Failed to retrieve nodes")

    def _create_snapshots(self) -> None:
        if self.nodes:
            for node in self.nodes:
                node = node.split('/')[1]
                url = self.url + "nodes/{0}/qemu".format(node)
                req = requests.get(url=url, headers=self.headers, verify=False)
                logging.info("Node: {0}".format(node))
                if req.status_code == 200:
                    data = req.json()['data']
                    for entry in data:
                        logging.info("Host: {0} : VMID: {1}".format(entry['name'],
                                                                    entry['vmid']))
                        self.hosts[entry['vmid']] = entry['name']
                        logging.info("VM: {0} : {1}".format(entry['vmid'], entry['name']))
                        snapshot_url = self.url + "nodes/{0}/qemu/{1}/snapshot".format(node, entry['vmid'])
                        now = datetime.now()
                        timestamp = now.strftime("%Y%m%d%H%M%S%f")
                        snap_name = entry['name'] + "_" + timestamp
                        payload = {
                            "node" : node,
                            "snapname" : snap_name,
                            "vmid" : entry['vmid']
                        }
                        req = requests.post(url=snapshot_url, headers=self.headers, json=payload, verify=False)
                        if req.status_code == 200:
                            logging.info("Successfully created: {0}".format(snap_name))
                        else:
                            logging.error("Failed to create: {0}".format(snap_name))
                else:
                    logging.error("Failed to retrieve nodes")
                
    
        
        
        