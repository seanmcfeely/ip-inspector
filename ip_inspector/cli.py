#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import sys
import json
import argparse
import argcomplete
import logging
from pprint import pprint
from ip_inspector.config import CONFIG, HOME_PATH, save, load
from ip_inspector import maxmind
from ip_inspector import Inspector

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')


def main():

    parser = argparse.ArgumentParser(description="Inspect IP address metadata for IDR purposes")
    parser.add_argument('-d', '--debug', default=False, action='store_true', help="Turn on debug logging.")
    parser.add_argument('-u', '--update-databases', default=False, action='store_true', help="Update the MaxMind GeoLite2 Databases")
    parser.add_argument('-r', '--raw-results', action='store_true', help="return results in their raw json format")
    parser.add_argument('-pp', '--pretty-print', action='store_true', help="Pretty print the raw json results")
    parser.add_argument('-i', '--ip', action='store', help="A single IP address to inspect.")
    parser.add_argument('-f', '--field',  action='append', dest='fields', default=[], choices=maxmind.FIELDS, help='specific fields to return')
    parser.add_argument('-csv', action='store_true', help="print fields as comma seperated with --from-stdin and fields")
    parser.add_argument('--from-stdin', action='store_true', help="Inspect each IP in a list of IP addresses passed to STDIN")
    parser.add_argument('-lk', '--license-key', action='store', help='MaxMind Liscense Key (saves to config for future use)')
    parser.add_argument('-a', '--alert-toggle', action='store_true', default=CONFIG['default']['alert'],
                        help="If True, Alert when a detection is made. Default configured state: {}".format(CONFIG['default']['alert']))
    parser.add_argument('-c', '--config-path', action='store', help='A YAML config to override the default config')

    subparsers = parser.add_subparsers(dest='command')

    wl_parser = subparsers.add_parser('whitelist', help="For interacting with the IP Network Organization whitelist")
    wl_parser.add_argument('-sp', '--show-path', action='store_true', help="Show the existing whitelist location.")
    wl_parser.add_argument('-a', '--add', action='store', help="Add entries to the whitelist by IP results.")
    wl_parser.add_argument('-r', '--remove', action='store', help="Remove entries to the whitelist by IP results.")
    wl_parser.add_argument('-p', '--print', action='store_true', help="Print the existing whitelist.")

    bl_parser = subparsers.add_parser('blacklist', help="For interacting with the IP Network Organization blacklist.")
    bl_parser.add_argument('-sp', '--show-path', action='store_true', help="Show the existing blacklist location.")
    bl_parser.add_argument('-a', '--add', action='store', help="Add entries to the blacklist by IP results.")
    bl_parser.add_argument('-r', '--remove', action='store', help="Remove entries to the blacklist by IP results.")
    bl_parser.add_argument('-p', '--print', action='store_true', help="Print the existing blacklist.")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.config_path:
        config = load(args.config_path)
    else:
        config = CONFIG

    if args.license_key:
        config['maxmind']['license_key'] = args.license_key
        save(config)
    
    if args.update_databases:
        maxmind.update_databases(license_key=config['maxmind']['license_key'])

    #mmc = maxmind.Client()
    mmc = Inspector(maxmind.Client())

    '''
    if args.command == 'blacklist':
        if args.add:
            ip = args.add
            if '/' in ip:
                ip = ip[:ip.rfind('/')]
            mmip = mmc.get(ip)
    '''

    # TODO Validate IP addresses?
    if args.from_stdin:
        if args.fields and args.csv:
            header = "IP/Network," + ','.join(args.fields)
            print(header)
        iplist = [line.strip() for line in sys.stdin]
        for ip in iplist:
            network = None
            if '/' in ip:
                network = ip
                ip = ip[:ip.rfind('/')]
            try:
                mmip = mmc.get(ip)
            except ValueError:
                logging.warning("{} is not a valid ipv4 or ipv6".format(ip))
            if mmip:
                if args.raw_results:
                    print(json.dumps(mmip.raw))
                elif args.pretty_print:
                    pprint(mmip.raw)
                elif args.fields:
                    result_string = "--> {}".format(network if network else mmip.ip)
                    if args.csv:
                        result_string = "{},".format(network if network else mmip.ip)
                    for field in args.fields:
                        if args.csv:
                            result_string += '"{}",'.format(mmip.get(field))
                        else:
                            result_string += " | {}: {}".format(field, mmip.get(field))
                    if result_string.endswith(','):
                        print(result_string[:-1])
                    else:
                        print(result_string)
                else:
                    print(mmip)
        return

    if args.ip:
        mmip = mmc.get(args.ip)
        if mmip:
            if args.raw_results:
                print(json.dumps(mmip.raw))
            elif args.pretty_print:
                pprint(mmip.raw)
            elif args.fields:
                for field in args.fields:
                    print(mmip.get(field))
            else:
                print(mmip)
        return
