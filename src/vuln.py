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
    data = {
    'cwe_id' : 'CWE-' + str(cwe),
    'cwe_name' : cwe_name
    }
    return data

if __name__ == '__main__':
    args = parser.parse_args()
    # get_vuln(args.a, args.v)
    session = requests.Session()
    # get_info('CVE-2019-1010298', session)
    get_vuln('test.com', 'nginx', '1.10.3')
