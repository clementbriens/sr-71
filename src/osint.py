from bs4 import BeautifulSoup
import requests
import re
import configparser
import os
import subprocess
from tqdm import tqdm
from pyexiftool import exiftool
import pprint


class OSINT():

    def __init__(self):
        self.target = ''
        self.exiftool = exiftool.ExifTool()
        self.pp = pprint.PrettyPrinter()

    def grabber(self, soup):
        grabber_data = {}
        grabber_data['telephone'] = []
        grabber_data['email'] = []
        grabber_data['social_media'] = {}
        grabber_data['web_endpoints'] = []
        grabber_data['legal_mentions'] = []
        grabber_data['custom_regex'] = {}
        grabber_data['documents'] = []

        config = configparser.ConfigParser()
        config.read('conf.ini')
        for socmedia in config['OSINT']['social_media'].split(';'):
            grabber_data['social_media'][socmedia] = []

        for regex in config['Regex']:
            grabber_data['custom_regex'][regex] = []

        links = soup.find_all('a', href=True)
        for link in links:

            if  link['href'].split(':')[0] == 'tel':
                grabber_data['telephone'].append(link['href'].split(':')[1])
            if 'mailto' in link['href']:
                grabber_data['email'].append(link['href'].split(':')[1])

            for socmedia in config['OSINT']['social_media'].split(';'):
                if socmedia in link['href']:
                    grabber_data['social_media'][socmedia].append(link['href'])

            if self.target in link['href']:
                if link['href'] not in grabber_data['web_endpoints'] and len(link['href']) > 0:
                    grabber_data['web_endpoints'].append(link['href'].split(self.target)[1])
                    if len(link['href'].split('/')[-1].split('.')) == 2 and 'aspx' not in link['href']and 'php' not in link['href']:
                        grabber_data['documents'].append(link['href'])


            try:
                if link['href'][0] == '/':
                    if link['href'] not in grabber_data['web_endpoints'] and len(link['href']) > 0:
                        grabber_data['web_endpoints'].append(link['href'])

                        if len(link['href'].split('/')[-1].split('.')) == 2 and 'aspx' not in link['href']:
                            grabber_data['documents'].append(link['href'])
            except:
                pass


        text = soup.find_all('p', text=True)
        for t in text:
            if '©' in t.get_text():
                grabber_data['legal_mentions'].append(t.get_text())

        for regex in config['Regex']:
            grabber_data['custom_regex'][regex].append(re.findall(str(config['Regex'][regex]), str(soup)))

        return grabber_data

    def meta_mage(self, documents):
        print('Getting documents')

        path = '{}/reports/{}/documents/'.format(os.path.abspath(os.getcwd()), self.target)
        try:
            os.mkdir(path)
        except:
            pass
        for document in tqdm(documents):
            prog = subprocess.Popen(['sudo', 'torsocks', 'wget', '-nc','-P', path, document], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            prog.communicate()

        files = os.listdir(path)
        for file in range(0, len(files)):
            files[file] = path + files[file]
        with self.exiftool as et:
            metadata = et.get_metadata_batch(files)
        return metadata



    # def test_request(self):
    #     user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.1916.47 Safari/537.36'
    #     r = requests.get(self.target, headers={'User-Agent': user_agent})
    #     return r.content

    def run(self, content, target):
        self.target = target
        try:
            os.mkdir('{}/reports/{}/documents'.format(os.path.abspath(os.getcwd())), self.target)
        except:
            pass
        osint_data = {}
        soup = BeautifulSoup(content, 'html.parser')
        grabber_data = self.grabber(soup)
        if len(grabber_data['documents']) > 0:
            grabber_data['metadata'] = self.meta_mage(grabber_data['documents'])
        return grabber_data
# if __name__ == '__main__':
#     osint = OSINT()
#     osint.run()
