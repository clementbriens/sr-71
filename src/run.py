import requests
import json
from cloak import Cloak
from osint import OSINT
from bs4 import BeautifulSoup
from multiprocessing import Pool
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

class BlackBird():

    def __init__(self):
        self.target = input('Target: ')
        self.domains = []
        self.data = []
        self.vulnerabilities = []
        self.technologies = []
        self.flying = False
        self.osint = True
        self.pp = pprint.PrettyPrinter()

    def enum_domains(self, target):
        url = 'https://crt.sh/?q={}&output=json'.format(target)
        r = requests.get(url)
        try:
            data = json.loads(r.content)
            for d in data:
                for subdomain in d['name_value'].split(','):
                    for s in subdomain.split('\n'):
                        if s not in self.domains:
                            self.domains.append(s)
            cloak.sprint(str(len(self.domains)) + ' domains found!')
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
        if code == 200:
            domain_data['technologies'] = self.detect_tech(domain)
        if code != 404 and self.osint == True:
            domain_data['osint'] = osint.run(r, self.target)
        else:
            domain_data['technologies'] = []

        return domain_data

    def export(self):
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
        #
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




        emails_df = pd.DataFrame(columns = ['domain', 'email'])
        legal_df = pd.DataFrame(columns = ['domain', 'legal'])
        socmedia_df = pd.DataFrame(columns = ['domain', 'platform', 'link'])
        telephone_df = pd.DataFrame(columns = ['domain', 'number'])

        for d in self.data:
            if 'osint' in d.keys():
                osint_data = d['osint']
                if len(osint_data['email']) > 0:
                    for email in osint_data['email']:
                        data = {
                        'domain' : d['domain'],
                        'email' : email
                        }
                        emails_df.loc[len(emails_df)] = data

                if len(osint_data['legal_mentions']) > 0:
                    for legal in osint_data['legal_mentions']:
                        data = {
                        'domain' : d['domain'],
                        'legal' : legal

                        }
                        legal_df.loc[len(emails_df)] = data

                for soc in osint_data['social_media'].keys():
                    for s in osint_data['social_media'][soc]:
                        if len(s) > 1:
                            data = {
                            'domain' : d['domain'],
                            'platform' : str(soc).capitalize(),
                            'link' : s
                            }
                            socmedia_df.loc[len(socmedia_df)] = data

                if len(osint_data['telephone']) > 0:
                    data = {
                    'domain' : d['domain'],
                    'number' : osint_data['telephone']
                    }
                    telephone_df.loc[len(telephone_df)] = data

        emails_df.to_csv('reports/{}/data/osint/{}_emails.csv'.format(self.target, self.target))
        legal_df.to_csv('reports/{}/data/osint/{}_legals.csv'.format(self.target, self.target))
        socmedia_df.to_csv('reports/{}/data/osint/{}_socmedia.csv'.format(self.target, self.target))
        telephone_df.to_csv('reports/{}/data/osint/{}_telephones.csv'.format(self.target, self.target))




    def run(self):
        self.enum_domains(self.target)
        # p = Pool(5)
        # self.data = p.map(self.flyover, self.domains)
        # p.daemon = True
        # p.close()
        # p.join()
        for domain in self.domains[:20]:
            # try:
            self.data.append(self.flyover(domain))
            # except:
            #     pass

        self.lookup_vulnerabilities()
        self.export()
        report.generate_report(self.target)



if __name__ == '__main__':
    blackbird = BlackBird()
    osint = OSINT()
    cloak = Cloak()
    blackbird.run()
