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

class ElasticMethods():

    def __init__(self, fqdn:str, key: str):
        self.headers = { "Authorization": f"ApiKey {key}",
                         "Content-Type": "application/json",
                         "kbn-xsrf": "reporting"}
        self.url = "https://{0}/api/".format(fqdn)

    def _gen_export_file_name(self, str_pfx: str, fmt: str) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = str_pfx + timestamp + fmt
        return filename
    
    def _get_agents(self) -> None:
        ''' Retrieve Elastic Agents '''
        try:
            url = self.url + 'fleet/agents?perPage=100'
            req = requests.get(url=url, headers=self.headers, verify=False)
            df = pd.DataFrame(req.json()['items'])
            filename = self._gen_export_file_name('elastic_agents_', '.xlsx')
            display(df)
            df.to_excel(filename, index=False)
        except Exception as e:
            logging.error("Exception raised: {0}".format(e))

    def _get_agent_actions(self) -> None:
        ''' Retrieve Elastic Agent Actions '''
        try:
            url = self.url + 'endpoint/action'
            req = requests.get(url=url, headers=self.headers, verify=False)
            logging.info(req.content)
            if req.status_code == 200:
                logging.info(req.json())
            else:
                logging.error("Failed to retrieve agent actions: {0}".format(req.status_code))
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def _get_open_alerts(self) -> list:
        ''' Retrieve open alerts '''
        signal_ids = []
        try:
            url = self.url + 'detection_engine/signals/search'
            payload = {
            "size": 10000,
              "query": {
                "bool": {
                  "filter": [
                    {
                      "bool": {
                        "must": [],
                        "filter": [
                          {
                            "match_phrase": {
                              "kibana.alert.workflow_status": "open"
                            }
                          }
                        ],
                        "should": [],
                        "must_not": [
                          {
                            "exists": {
                              "field": "kibana.alert.building_block_type"
                            }
                          }
                        ]
                      }
                    },
                    {
                      "range": {
                        "@timestamp": {
                          "gte": "now-1y",
                          "lte": "now"
                        }
                      }
                    }
                  ]
                }
              },
            }
            req = requests.post(url=url, headers=self.headers, json=payload, verify=False)
            if req.status_code == 200:
                logging.info("Alert query returned: {0} entries".format(len(req.json()['hits']['hits'])))
                df = pd.DataFrame(req.json()['hits']['hits'])
                filename = self._gen_export_file_name('elastic_alerts_', '.xlsx')
                df.to_excel(filename, index=False)
                for alert in req.json()['hits']['hits']:
                    logging.info(alert['_id'])
                    signal_ids.append(alert['_id'])
                return signal_ids
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))

    def _close_open_alerts(self, signal_ids:list) -> None:
        payload = {
          "status": "closed",
          "signal_ids": signal_ids
        }
        try:
            url = self.url + "detection_engine/signals/status"
            req = requests.post(url=url, headers=self.headers, json=payload, verify=False)
            if req.status_code == 200:
                logging.info("Successfully closed: {0} alerts".format(len(signal_ids)))
            else:
                logging.error("Failed to close alerts")
        except Exception as e:
            logging.exception("Exception raised: {0}".format(e))
    