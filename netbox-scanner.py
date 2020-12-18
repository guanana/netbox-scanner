#!/usr/bin/env python3

import logging
import os
import sys
from argparse import ArgumentParser
from configparser import ConfigParser
from datetime import datetime
from os.path import expanduser, isfile

from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning

from nbs import NetBoxScanner

argument = str(sys.argv[1])

if argument == 'nmap':
    from nbs.nmap import Nmap
if argument == 'netxms':
    from nbs.netxms import NetXMS
if argument == 'prime':
    from nbs.prime import Prime


local_config = expanduser('~/.netbox-scanner.conf')
global_config = '/opt/netbox/netbox-scanner.conf'
dir_config = './netbox-scanner.conf'
config = ConfigParser()

if isfile(local_config):
    config.read(local_config)
elif isfile(global_config):
    config.read(global_config)
elif isfile(dir_config):
    config.read(dir_config)
else:
    raise FileNotFoundError('Configuration file was not found.')


def check_env(conf):
    conf_with_env = {}
    for each_section in conf.sections():
        section_dict = {}
        for (k, v) in conf.items(each_section):
            try:
                section_dict.update({k: os.environ["{0}_{1}".format(each_section, str(k).upper())]})
            except KeyError:
                section_dict.update({k: v})
        conf_with_env.update({each_section: section_dict})

    return conf_with_env

config = check_env(config)

netbox = config['NETBOX']
if argument == 'nmap':
    nmap = config['NMAP']
if argument == 'netxms':
    netxms = config['NETXMS']
if argument == 'prime':
    prime = config['PRIME']

parser = ArgumentParser(description='netbox-scanner')
subparsers = parser.add_subparsers(title='Commands', dest='command')
subparsers.required = True
if argument == 'nmap':
    argsp = subparsers.add_parser('nmap', help='Nmap module')
if argument == 'netxms':
    argsp = subparsers.add_parser('netxms', help='NetXMS module')
if argument == 'prime':
    argsp = subparsers.add_parser('prime', help='Cisco Prime module')
args = parser.parse_args()

logfile = '{}/netbox-scanner-{}.log'.format(
    netbox['logs'],
    datetime.now().isoformat()
)
logging.basicConfig(
    filename=logfile,
    level=logging.INFO,
    format='%(asctime)s\tnetbox-scanner\t%(levelname)s\t%(message)s'
)
logging.getLogger().addHandler(logging.StreamHandler())

# useful if you have tls_verify set to no
disable_warnings(InsecureRequestWarning)

with open(nmap['networks'], 'r') as file:
    networks = file.readlines()

def cmd_nmap(s):  # nmap handler
    h = Nmap(nmap['unknown'], networks)
    h.run()
    s.sync(h.hosts)


def cmd_netxms(s):  # netxms handler
    h = NetXMS(
        netxms['address'],
        netxms['username'],
        netxms['password'],
        bool(netxms['tls_verify']),
        netxms['unknown']
    )
    h.run()
    s.sync(h.hosts)


def cmd_prime(s):  # prime handler
    h = Prime(
        prime['address'],
        prime['username'],
        prime['password'],
        bool(prime['tls_verify']),
        prime['unknown']
    )
    h.run()  # set access_point=True to process APs
    s.sync(h.hosts)


if __name__ == '__main__':
    scanner = NetBoxScanner(
        netbox['address'],
        netbox['token'],
        netbox['tls_verify'],
        nmap['tag'],
        bool(nmap['cleanup'])
    )

    if args.command == 'nmap':
        logging.info(f'Nmap scan started')
        cmd_nmap(scanner)
    elif args.command == 'netxms':
        logging.info(f'netxms scan started')
        scanner.tag = 'netxms'
        scanner.cleanup = bool(netxms['cleanup'])
        cmd_netxms(scanner)
    elif args.command == 'prime':
        logging.info(f'prime scan started')
        scanner.tag = prime['tag']
        scanner.cleanup = bool(prime['cleanup'])
        cmd_prime(scanner)

    exit(0)
