import requests
import json
from cloak import Cloak
from bs4 import BeautifulSoup
from wad import detection
import os
import subprocess
from wad import *
from bs4 import BeautifulSoup
import socks
import socket
import pandas as pd
import vuln
import report
from ast import literal_eval
import sys
import argparse
import dateparser
from datetime import datetime




class BlackBird():

    def get_args(self):
        ap = argparse.ArgumentParser()
        ap.add_argument("-d","--domain", required=True,help="Master domain to recon.")
        ap.add_argument("-j","--json", action='store_true', help="JSON export of vulnerabilities and domain data.")


        return vars(ap.parse_args())
    def __init__(self):
        self.now = dateparser.parse(str(datetime.now()))
        self.args = self.get_args()
        self.target = self.args['domain']
        self.certs = []
        self.domains = []
        self.data = []
        self.vulnerabilities = []
        self.technologies = []
        self.pp = pprint.PrettyPrinter()

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
        # result = subprocess.check_output(['wad', '-u', website])
        result = Detector().detect(website)
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
                        if len(data) > 0:
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
            with open('{}_vulnerabilities.json'.format(self.target), 'w', encoding='utf-8') as f:
                json.dump(self.vulnerabilities, f, ensure_ascii=False, indent=4)
                print('{}_vulnerabilities.json'.format(self.target), 'saved to folder.')

            with open('{}_domains.json'.format(self.target), 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=4)
                print('{}_domains.json'.format(self.target), 'saved to folder.')

        self.pp.pprint(self.data)
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

        try:
            os.mkdir('reports/' + self.target + '/data/osint/')
        except:
            pass


        domains_df = pd.DataFrame(columns = ['domain', 'response', 'technologies'])

        for d in self.data:
            techs = []
            for t in d['technologies']:
                if t['ver'] != None:
                    techs.append(str('{} {}'.format(t['app'], t['ver'])))
                else:
                    techs.append(str('{}'.format(t['app'])))
            data = {
            "domain" : d['domain'],
            'response' : d['response'],
            'technologies' : ', '.join(techs)
            }

            domains_df.loc[len(domains_df)] = data
        domains_df.to_csv('reports/{}/data/{}_domains.csv'.format(self.target, self.target))

        tech_df = pd.DataFrame(columns = ['technology', 'version', 'type'])
        for d in self.data:
            tech_data = []
            for t in d['technologies']:
                if t not in tech_data:
                    tech_data.append(t)
                    data = {
                    'technology' : t['app'],
                    'version' : t['ver'],
                    'type' : t['type']

                    }
                    tech_df.loc[len(tech_df)] = data

        tech_df.to_csv('reports/{}/data/{}_technologies.csv'.format(self.target, self.target))

        cwe_df = pd.DataFrame(columns = ['domain', 'cve', 'cwe_id', 'cwe_name', 'cwe_description'])
        cwes = []
        for d in self.vulnerabilities:
            domain = d['domain']

            for cve in d['cves']:
                for cwe in cve['cwes']:
                    data = {
                    'domain' : domain,
                    'cve' : cve['cve_name'],
                    'cwe_id' : cwe['cwe_id'],
                    'cwe_name' : cwe['cwe_name'],
                    'cwe_description' : cwe['cwe_description']
                    }
                    cwe_df.loc[len(cwe_df)] = data

        cwe_df.to_csv('reports/{}/data/{}_cwes.csv'.format(self.target, self.target))

        impact_df = pd.DataFrame(columns = ['domain', 'cve', 'cwe_id', 'impact_scope', 'impact_desc'])
        # self.pp.pprint(self.vulnerabilities)
        triad = ['Accessibility', 'Confidentiality', 'Integrity']
        for d in self.vulnerabilities:
            domain = d['domain']
            for cve in d['cves']:
                for cwe in cve['cwes']:
                    for impact in cwe['cwe_impact']:
                        for scope in impact['scope']:
                            if scope in triad:

                                desc = impact['description']

                                data : {
                                'domain' : domain,
                                'cve' : cve['cve_name'],
                                'cwe_id' : cwe['cwe_name'],
                                'impact_scope' : scope,
                                'impact_desc' : desc
                                }
                                impact_df.loc[len(impact_df)] = data
        print(impact_df)
        impact_df.to_csv('reports/{}/data/{}_impact.csv'.format(self.target, self.target))

        vulns_df = pd.DataFrame(columns = ['domain', 'technology', 'vulnerability', 'severity', 'vulnerability_types'])
        for d in self.vulnerabilities:
            for cve in d['cves']:

                data = {
                'domain' : d['domain'],
                'technology' : d['tech'],
                'vulnerability' : cve['cve_name'],
                'severity' : cve['cvss'],
                'vulnerability_types' : ', '.join(cve['vulnerability_types'])
                }
                vulns_df.loc[len(vulns_df)] = data
        vulns_df.to_csv('reports/{}/data/{}_vulns.csv'.format(self.target, self.target))

        certs = pd.DataFrame(columns = ['issuer_name','domain','id', 'not_before', 'not_after', 'expired'])
        for c in self.certs:
            c_data = {}
            c_data['issuer_name'] = c['issuer_name']
            c_data['domain'] = c['name_value']
            c_data['id'] = c['id']
            c_data['not_before'] = c['not_before']
            c_data['not_after'] = c['not_after']

            if dateparser.parse(c['not_after']) < self.now:
                c_data['expired'] = True
            else:
                c_data['expired'] = False
            certs.loc[len(certs)] = c_data
        expired_certs = pd.DataFrame(columns = ['issuer_name','domain','id', 'not_before', 'not_after', 'expired'])
        certs['not_after'] = pd.to_datetime(certs['not_after'])
        for d in certs['domain'].unique():
            max = certs.loc[(certs['domain'] == d) & (certs['not_after']< self.now)]['not_after'].max()
            exp = certs.loc[(certs['domain'] ==d ) & (certs['not_after'] == max)]
            exp = exp.drop_duplicates(subset = 'not_after', keep='first')
            if len(exp) > 0:
                for index, row in exp.iterrows():
                    expired_certs.loc[len(expired_certs)] = row
        print(expired_certs)
        expired_certs.to_csv('reports/{}/data/{}_expired_certs.csv'.format(self.target, self.target))



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
    cloak = Cloak()

    blackbird.run()
