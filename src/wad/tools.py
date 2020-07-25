# Module tools
#
# Author: Sebastian Lopienski <Sebastian.Lopienski@cern.ch>
from __future__ import absolute_import, division, print_function, unicode_literals


from hashlib import md5
import logging
import sys
import ssl

import sys

import socks
import socket
from urllib3 import ProxyManager
import requests


socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, "127.0.0.1", 9050)

# patch the socket module
socket.socket = socks.socksocket


import six

def count(d, e):
    # TODO: Use collections.Counter once moved to python 2.7
    if type(e) == list:
        for i in e:
            count(d, i)
    else:
        if e in d:
            d[e] += 1
        else:
            d[e] = 1


def hash_id(x):
    return md5(("%s" % x).encode('utf-8')).hexdigest()[:8]

def getaddrinfo(*args):
  return [(socket.AF_INET, socket.SOCK_STREAM, 6, '', (args[0], args[1]))]


def urlopen(url, timeout):
    headers = {'User-Agent': 'Mozilla/5.0 Firefox/33.0'}
    session = requests.session()
    session.proxies = {'http':  'socks5://127.0.0.1:9050',
                       'https': 'socks5://127.0.0.1:9050'}
    ip = session.get('http://almien.co.uk/m/tools/net/ip/', headers = headers).text.split("IPv4: ")[1].split('<')[0]
    print('WAD IP:', ip)
    r = session.get(url, headers = headers)
    return r




def error_to_str(e):
    return str(e).replace('\n', '\\n')


def add_log_options(parser):
    parser.add_option("-q", "--quiet", action="store_true", dest="quiet", default=False,
                      help="be quiet")

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose", default=False,
                      help="be verbose")

    parser.add_option("-d", "--debug", action="store_true", dest="debug", default=False,
                      help="be more verbose")

    parser.add_option("--log", action="store", dest="log_file", metavar="FILE", default=None,
                      help="log to a file instead to standard output")


def use_log_options(options):
    log_format = '%(asctime)s (' + hash_id(options.__str__()) + '):%(module)s:%(levelname)s %(message)s'

    date_format = '%Y/%m/%d-%H:%M:%S'
    log_level = logging.WARNING

    if options.verbose:
        log_level = logging.INFO
    if options.debug:
        log_level = logging.DEBUG
    if options.quiet:
        log_level = logging.ERROR

    if options.log_file:
        logging.basicConfig(filename=options.log_file, level=log_level, format=log_format, datefmt=date_format)
    else:
        logging.basicConfig(stream=sys.stdout, level=log_level, format=log_format, datefmt=date_format)
