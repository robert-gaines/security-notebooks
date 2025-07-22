from IPython.display import display
import pandas as pd
import requests
import logging
import time
import time

logging.basicConfig(format='%(asctime)s %(message)s',
                    datefmt='%m/%d/%Y %I:%M:%S %p',
                    level=logging.INFO)

class BGPViewMethods():

    def __init__(self, addr:str) -> None:
        self.url = "https://api.bgpview.io/ip/{0}".format(addr)

    def _gen_export_file_name(self, str_pfx: str, fmt: str) -> str:
        timestamp = time.ctime()
        timestamp = timestamp.replace(':','_')
        timestamp = timestamp.replace(" ","_")
        filename = str_pfx + '_' + timestamp + fmt
        return filename
    
    def _transmit_query(self) -> None:
        req = requests.get(url=self.url)
        if req.status_code == 200:
            req = req.json()
            ip  = req['data']['ip']
            ptr = req['data']['ptr_record']
            prefixes  = req['data']['prefixes'][0]
            asn_data = prefixes['asn']
            rir = req['data']['rir_allocation']
            iana = req['data']['iana_assignment']
            maxmind = req['data']['maxmind']
            data = {
                'IP': ip,
                'Prefix': prefixes['prefix'],
                'Prefix IP': prefixes['ip'],
                'Prefix CIDR': prefixes['cidr'],
                'Prefix ASN': prefixes['asn'],
                'ASN': asn_data['asn'],
                'ASN Name': asn_data['name'],
                'Description': asn_data['description'],
                'Country Code': asn_data['country_code'],
                'RIR Name': rir['rir_name'],
                'Country Code': rir['country_code'],
                'RIR IP': rir['ip'],
                'RIR CIDR': rir['cidr'],
                'RIR Prefix': rir['prefix'],
                'RIR Date Allocated': rir['date_allocated'],
                'RIR Allocation Status': rir['allocation_status'],
                'IANA Assignment Status': iana['assignment_status'],
                'IANA Description': iana['description'],
                'WHOIS Server': iana['whois_server'],
                'IANA Date Assigned': iana['date_assigned'],
                'Country Code': maxmind['country_code'],
                'City': maxmind['city']
            }
            df = pd.DataFrame(data)
            display(df)
            filename = self._gen_export_file_name(ip, '.xlsx')
            df.to_excel(filename, index=False)
        else:
            logging.info("Failed to retrieve data")
            