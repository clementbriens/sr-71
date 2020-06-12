import requests
from bs4 import BeautifulSoup
import argparse
import socks
import socket
import _socket
import re

parser = argparse.ArgumentParser(description='Process some integers.')
parser.add_argument('-a', metavar = 'a')
parser.add_argument('-v', metavar = 'v')

def get_vuln(domain, app, ver):
    socks.setdefaultproxy()
    session = requests.Session()
    vuln_url = 'https://www.cvedetails.com/version-search.php?vendor=&product={}&version={}'.format(app , ver)
    user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:8.0) Gecko/20100101 Firefox/8.0'
    r = session.get(vuln_url ,headers={'User-Agent': user_agent})
    soup = BeautifulSoup(r.content, 'html.parser')

    try:
        table = soup.find('table', {'id' :'vulnslisttable'})

        cve_rows = table.find_all('td', {"nowrap" : ""})
        cves = []
        vulns = []
        for cve_row in cve_rows:

            s_vulns = cve_row.findAll('a', {'title': lambda x: x and 'CVE' in x.split('-')})
            if len(s_vulns) > 0:
                vulns.append(str(s_vulns).split('>')[1].split('<')[0])

        for vuln in vulns:
            data = get_cve_info(vuln, session)
            cves.append(data)

        data = {
        'domain' : domain,
        'tech' : app + ' ' + ver,
        'cves' : cves
        }
        return data
    except:
        return []


def get_cve_info(cve, session):
    cve_url = 'https://www.cvedetails.com/cve/' + str(cve)
    r = session.get(cve_url)
    soup = BeautifulSoup(r.content, 'html.parser')
    cvss = soup.find('div', {'class' : 'cvssbox'}).get_text()
    vuln_types = []
    vts = soup.findAll('span', {'class': lambda x: x and 'vt' in x.split('_')})
    for v in vts:
        vuln_types.append(str(v).split('>')[1].split('<')[0])

    cwe_list = []
    cwes = soup.findAll('a', {'title': lambda x: x and 'CWE' in x.split('-')})
    for c in cwes:
        cwe_list.append(str(c).split('>')[1].split('<')[0])
    cwe_data = []
    for cwe in cwe_list:
        data = get_cwe_info(cwe, session)
        cwe_data.append(data)

    cve_data = {
    'cve_name' : cve,
    'cvss' : cvss,
    'vulnerability_types' : vuln_types,
    'cwes': cwe_data
    }
    return cve_data



def get_cwe_info(cwe, session):
    cwe_url = 'https://cwe.mitre.org/data/definitions/' + str(cwe)
    r = session.get(cwe_url)
    soup = BeautifulSoup(r.content, 'html.parser')
    cwe_name = soup.find('h2').get_text().split(': ')[1]
    cwe_description = soup.find('div', {'id' : 'Description'}).find('div', {'class' : 'indent'}).get_text()
    impact_table  = soup.find('div', {'id' : 'Common_Consequences'}).find_all('tr')
    impact_list = []
    for row in impact_table[1:]:
        impact_data = {}
        impact_data['scope'] = re.findall('[A-Z][^A-Z]*', row.find('td', {'valign' : 'middle'}).get_text())
        impact_data['description'] = row.find_all('div', {'style' : 'padding-top:5px'})[1].get_text()
        impact_list.append(impact_data)


    data = {
    'cwe_id' : 'CWE-' + str(cwe),
    'cwe_name' : cwe_name,
    'cwe_description' : cwe_description,
    'cwe_impact' : impact_list,
    'cwe_mitigation' : get_mitigation_info(cwe, session)
    }
    return data

def get_mitigation_info(cwe, session):
    try:
        mit_url = 'https://cwe.mitre.org/data/definitions/{}.html'.format(cwe)
        r = session.get(mit_url)
        soup = BeautifulSoup(r.content, 'html.parser')
        table = soup.find('div', {'id' : 'Potential_Mitigations'})
        mitigation_data =[]
        for row in table.find_all('tr'):
            mitigation = {}
            mitigation['phase'] = row.find('p', {'class' : 'subheading'}).get_text().split('Phase: ')[1]
            text = row.find_all('div', {'class' : 'indent'})
            texts = []
            for t in text:
                if t.get_text != '':
                    texts.append(t.get_text())
            mitigation['text'] = ' '.join(texts)
            mitigation_data.append(mitigation)
        return mitigation_data
    except:
        return ['No known mitigations found']

if __name__ == '__main__':
    args = parser.parse_args()
    # get_vuln(args.a, args.v)
    session = requests.Session()
    # get_info('CVE-2019-1010298', session)
    get_vuln('test.com', 'nginx', '1.10.3')
    # get_mitigation_info(400, session)
