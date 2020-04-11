
import requests
from colorama import Fore

from stem import Signal
from stem.control import Controller
import socks

class Cloak():

    def get_tor_session(self):

        session = requests.session()

        session.proxies = {'http':  'socks5://127.0.0.1:9050',
                           'https': 'socks5://127.0.0.1:9050'}

        return session

    def get_original_ip(self):
        socks.setdefaultproxy()
        clear_session = requests.Session()
        return requests.get(' \n' + 'http://ipecho.net/plain').text

    def __init__(self):
        print('Cloak activated')
        self.tor_password = 'sr-71'
        self.original_ip = self.get_original_ip()
        self.session = self.get_tor_session()
        self.cur_ip = self.session.get(' \n' + 'http://ipecho.net/plain').text
        print(Fore.GREEN + self.cur_ip + ' connected')


    def sprint(self, text):
        if self.cur_ip != self.original_ip:
            print(Fore.WHITE + '(' + Fore.GREEN + str(self.cur_ip) +  Fore.WHITE + ') : ' +  str(text))
        else:
            print(Fore.WHITE + '(' + Fore.RED + str(self.cur_ip) +  Fore.WHITE + ') : ' +  str(text))

    def get(self, url):
        r = None
        try:
            r  =  self.session.get(url)
            code = r.status_code
        except:
            code = 404

        if code == 200:
            self.sprint(Fore.GREEN + str(code) + ' ' + Fore.WHITE + url)
        elif code == 403 or code == 401:
            self.sprint(Fore.YELLOW + str(code) + ' ' + Fore.WHITE + url)
        else:
            self.sprint(Fore.RED + str(code)+ ' ' + Fore.WHITE + url)

        if r:
            print(r)
            return r.content, code


    def rotate():
        print(' \n' + Fore.RED + 'Rotating TOR identity')
        old_ip = self.cur_ip
        self.renew_connection()
        self.cur_ip = tr.get('http://ipecho.net/plain').text
        if self.cur_ip == old_ip:
            rotate()
        else:
            print(Fore.GREEN + self.cur_ip + ' connected')
