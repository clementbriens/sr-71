import requests
import json
from utils.cloak import Cloak
import os
from wad import *
import pandas as pd
from utils import vuln, report
from utils.export import Exporter
import sys
import argparse

class BlackBird():

    def get_args(self):
        ap = argparse.ArgumentParser()
        ap.add_argument("-d","--domain", required=True,help="Master domain to recon.")
        ap.add_argument("-j","--json", action='store_true', help="JSON export of vulnerabilities and domain data.")
        ap.add_argument("-q","--quiet", action='store_true', default=False, help="Enable quiet mode.")
        ap.add_argument("-t","--timeout", type=int, default=5, help="Set request timeout.")
        return vars(ap.parse_args())

    def title(self):
        print('''                   .                             .
                  //                             \\\\
                 //                               \\\\
                //                                 \\\\
               //                _._                \\\\
            .---.              .//|\\.              .---.
  ________ / .-. \_________..-~ _.-._ ~-..________ / .-. \_________
           \ ~-~ /   /H-     `-=.___.=-'     -H\   \ ~-~ /
             ~~~    / H          [H]          H \    ~~~
                   / _H_         _H_         _H_ \\
                    (UUU         UUU         UUU)

===================================================================

SR-71 Domain enumeration and vulnerability analysis tool
By Clement Briens
https://github.com/clementbriens/

ASCII art: https://asciiart.website

==================================================================
                     ''')

    def __init__(self):
        self.title()
        self.args = self.get_args()
        self.target = self.args['domain']
        self.certs = []
        self.domains = []
        self.data = []
        self.vulnerabilities = []
        self.technologies = []

    def enum_domains(self, target):
        certs = pd.DataFrame(columns = ['domain', 'not_after'])
        url = 'https://crt.sh/?q={}&output=json'.format(target)
        r = requests.get(url)
        try:
            data = json.loads(r.content)
            for d in data:
                for subdomain in d['name_value'].split(','):
                    for s in subdomain.split('\n'):
                        if s not in self.domains:
                            self.domains.append(s)
                        cert_data = d
                        cert_data['name_value'] = s
                        self.certs.append(cert_data)
        except:
            print('Crt.sh not responding. Please try again.')
            sys.exit()

    def detect_tech(self, domain):
        website = 'https://' + domain
        try:
            result = Detector().detect(website)
        except:
            cloak.sprint('WAD detection failed')
            return []
        try:
            for r in result:
                if r not in self.technologies:
                    self.technologies.append(r)
            return result[website + '/']
        except:
            return []

    def lookup_vulnerabilities(self):
        for domain in self.data:
            for tech_info in domain['technologies']:
                if tech_info['ver'] != None:
                    data = vuln.get_vuln(domain['domain'], tech_info['app'], tech_info['ver'])
                    if data not in self.vulnerabilities:
                        if data:
                            self.vulnerabilities.append(data)

    def flyover(self, domain):
        data = cloak.get('http://' + domain)
        try:
            code = data[1]
            r = data[0]
        except:
            code = 404

        domain_data = {}
        domain_data['domain'] = domain
        domain_data['response'] = code
        if code != 404:
            domain_data['technologies'] = self.detect_tech(domain)
        else:
            domain_data['technologies'] = []

        self.data.append(domain_data)

    def export(self):
        if self.args['json']:
            with open('{}/data/{}_vulnerabilities.json'.format(self.target, self.target), 'w', encoding='utf-8') as f:
                json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=4)
                print('{}_vulnerabilities.json'.format(self.target), 'saved to folder.')

            with open('{}/data/{}_domains.json'.format(elf.target, self.target), 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=4)
                print('{}_domains.json'.format(self.target), 'saved to folder.')

        try:
            os.mkdir('reports/')
        except:
            pass
        try:
            os.mkdir('reports/' + self.target + '/')
        except:
            pass
        try:
            os.mkdir('reports/' + self.target +  '/data/')
            os.mkdir('reports/' + self.target +  '/plots/')
        except:
            pass

        ex = Exporter(self.target,
        self.data,
        self.certs,
        self.vulnerabilities)
        ex.export_all()



    def run(self):
        if self.target:
            print('Scanning', self.target)
            self.enum_domains(self.target)

            for domain in self.domains:
                self.flyover(domain)

            self.lookup_vulnerabilities()
            self.export()
            report.generate_report(self.target)
        else:
            sys.exit()



if __name__ == '__main__':
    blackbird = BlackBird()
    cloak = Cloak(blackbird.args)
    blackbird.run()
