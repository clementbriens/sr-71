import pandas as pd
import dateparser
from datetime import datetime

class Exporter:
    def __init__(self, target, data, certs, vulnerabilities):
        self.target = target
        self.data = data
        self.certs = certs
        self.vulnerabilities = vulnerabilities
        self.now = dateparser.parse(str(datetime.now()))

    def export_domains(self):
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
        domains_df.to_csv('reports/{}/data/{}_domains.csv'.format(self.target,self.target))

    def export_tech(self):
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

    def export_cwes(self):
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

    def export_vulns(self):
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

    def export_certs(self):
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
        certs.to_csv('reports/{}/data/{}_certs.csv'.format(self.target, self.target))
        expired_certs.to_csv('reports/{}/data/{}_expired_certs.csv'.format(self.target, self.target))

    def export_all(self):
        self.export_tech()
        self.export_cwes()
        self.export_certs()
        self.export_domains()
        self.export_vulns()
