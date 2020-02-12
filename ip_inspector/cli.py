#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import os
import sys
import json
import argparse
import argcomplete
import logging
from pprint import pprint
from ip_inspector.config import CONFIG, WORK_DIR, save, load
from ip_inspector import maxmind, tor
from ip_inspector import Inspector, append_to_, remove_from_

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - [%(levelname)s] %(message)s')


def main():

    parser = argparse.ArgumentParser(description="Inspect IP address metadata for IDR purposes")
    parser.add_argument('-d', '--debug', default=False, action='store_true', help="Turn on debug logging.")
    parser.add_argument('-u', '--update-databases', default=False, action='store_true', help="Update the MaxMind GeoLite2 Databases")
    parser.add_argument('-r', '--raw-results', action='store_true', help="return results in their raw json format")
    parser.add_argument('-pp', '--pretty-print', action='store_true', help="Pretty print the raw json results")
    parser.add_argument('-i', '--ip', action='store', help="A single IP address to inspect.")
    parser.add_argument('--print-tor-exits', action='store_true', help="Get tor exist nodes")
    parser.add_argument('-f', '--field',  action='append', dest='fields', default=[], choices=maxmind.FIELDS, help='specific fields to return')
    parser.add_argument('-csv', action='store_true', help="print fields as comma seperated with --from-stdin and fields")
    parser.add_argument('--from-stdin', action='store_true', help="Inspect each IP in a list of IP addresses passed to STDIN")
    parser.add_argument('-lk', '--license-key', action='store', help='MaxMind Liscense Key (saves to config for future use)')
    # Alerting not implemented
    #parser.add_argument('-a', '--alert-toggle', action='store_true', default=CONFIG['default']['alert'],
    #                    help="If True, Alert when a detection is made. Default configured state: {}".format(CONFIG['default']['alert']))
    parser.add_argument('-c', '--config-path', action='store',
        help='A JSON config to override the default configuration. The path is saved for future use.')
    help_note = ("Write a copy of the existing configuration to the local config path for easily making configuration overrides, "
                 "changes, or updates. Edit the local config to meet your needs.")
    parser.add_argument('--customize', action='store_true', help=help_note)

    subparsers = parser.add_subparsers(dest='command')

    wl_parser = subparsers.add_parser('whitelist', help="For interacting with the IP Network Organization whitelist")
    wl_parser.add_argument('-sp', '--show-path', action='store_true', help="Show the existing whitelist location.")
    wl_parser.add_argument('-p', '--print', action='store_true', help="Print the existing whitelist.")
    wl_subparser = wl_parser.add_subparsers(dest='wl_command')
    wl_add_parser = wl_subparser.add_parser('add', help="Append to a whitelist.")
    wl_add_parser.add_argument('ip', help="The IP address to work with.")
    wl_add_parser.add_argument('-t', '--whitelist-type', action='append', default=['ORG'], choices=CONFIG['default']['whitelists'].keys(),
                                help="The type of metadata from this IP result that should be whitelisted. Can specify multiple times.")
    wl_remove_parser = wl_subparser.add_parser('remove', help="Remove a whitelist entry.")
    wl_remove_parser.add_argument('ip', help="The IP address to work with.")
    wl_remove_parser.add_argument('-t', '--whitelist-type', action='append', default=['ORG'], choices=CONFIG['default']['whitelists'].keys(),
                                help="The type of metadata from this IP result that should be removed from the respective whitelist. Can specify multiple times.")
   

    bl_parser = subparsers.add_parser('blacklist', help="For interacting with the IP Network Organization blacklist.")
    bl_parser.add_argument('-sp', '--show-path', action='store_true', help="Show the existing blacklist location.")
    bl_parser.add_argument('-p', '--print', action='store_true', help="Print the existing blacklist.")
    bl_subparser = bl_parser.add_subparsers(dest='bl_command')
    bl_add_parser = bl_subparser.add_parser('add', help="Append to a blacklist.")
    bl_add_parser.add_argument('ip', help="The IP address to work with.")
    bl_add_parser.add_argument('-t', '--blacklist-type', action='append', default=['ORG'], choices=CONFIG['default']['blacklists'].keys(),
                                help="The type of metadata from this IP result that should be blacklisted. Can specify multiple times.")
    bl_remove_parser = bl_subparser.add_parser('remove', help="Remove a blacklist entry.")
    bl_remove_parser.add_argument('ip', help="The IP address to work with.")
    bl_remove_parser.add_argument('-t', '--blacklist-type', action='append', default=['ORG'], choices=CONFIG['default']['blacklists'].keys(),
                                help="The type of metadata from this IP result that should be removed from the respective blacklist. Can specify multiple times.")

    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.print_tor_exits:
        for EN in tor.ExitNodes().exit_nodes:
            print(EN)

    if args.config_path:
        if not os.path.exists(args.config_path):
            print("That file doesn't exist.")
            return
        # TODO weird bug.. if there is a saved config the logging configuration is wiped.
        logging.warning("KNOWN BUG: if there is a saved config the logging configuration is wiped.")
        save({'default': { 'saved_config_path': args.config_path}})
        config = load()
    else:
        config = CONFIG

    if args.customize:
        # save will write the existing loaded configuration to the SAVED_CONFIG_PATH
        if save(config, config_path='ip_inspector.config.json'):
            print("Wrote the existing configuration to: ip_inspector.config.json")
            print("Make any changes to that configuration file and then supply it to `ip-inspector --config-path`")
        return

    if args.license_key:
        data = {}
        data['maxmind'] = {'license_key': args.license_key}
        #data['default'] = {'work_dir': config['default']['work_dir']}
        save(data)
        # put it in the right place so this session can continue
        config['maxmind']['license_key'] = args.license_key
    
    if args.update_databases:
        if not maxmind.update_databases(license_key=config['maxmind']['license_key']):
            return 1

    mmi = Inspector(maxmind.Client(license_key=config['maxmind']['license_key']))


    if args.command == 'blacklist' or args.command == 'whitelist':
        if args.show_path or args.print:
            loaded_lists = config['default'][args.command+'s']
            for _l, _path in loaded_lists.items():
                if os.path.exists(_path):
                    full_path = _path
                else:
                    full_path = os.path.join(WORK_DIR, _path)
                if args.show_path:
                    print("{}: {}".format(_l, full_path))
                if args.print:
                    if os.path.exists(full_path):
                        with open(full_path, 'r') as fp:
                            print(fp.read())
            return
        if args.ip:
            ip = args.ip
            if '/' in ip:
                ip = ip[:ip.rfind('/')]
            iip = mmi.inspect(ip)
        if args.command == 'blacklist':
            if args.bl_command == 'add':
                for bl_type in list(set(args.blacklist_type)):
                    blacklist_path = config['default']['blacklists'][bl_type]
                    append_to_('blacklist', iip, field=bl_type, list_path=blacklist_path)
            elif args.bl_command == 'remove':
                for bl_type in list(set(args.blacklist_type)):
                    blacklist_path = config['default']['blacklists'][bl_type]
                    remove_from_('blacklist', iip, field=bl_type, list_path=blacklist_path)
        if args.command == 'whitelist':
            if args.wl_command == 'add':
                for wl_type in list(set(args.whitelist_type)):
                    whitelist_path = config['default']['whitelists'][wl_type]
                    append_to_('whitelist', iip, field=wl_type, list_path=whitelist_path)
            elif args.wl_command == 'remove':
                for wl_type in list(set(args.whitelist_type)):
                    whitelist_path = config['default']['whitelists'][wl_type]
                    remove_from_('whitelist', iip, field=wl_type, list_path=whitelist_path)
        return

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
                iip = mmi.inspect(ip)
            except ValueError:
                logging.warning("{} is not a valid ipv4 or ipv6".format(ip))
            if iip:
                if args.raw_results:
                    print(json.dumps(iip.raw))
                elif args.pretty_print:
                    pprint(iip.raw)
                elif args.fields:
                    result_string = "--> {}".format(network if network else iip.ip)
                    if args.csv:
                        result_string = "{},".format(network if network else iip.ip)
                    for field in args.fields:
                        if args.csv:
                            result_string += '"{}",'.format(iip.get(field))
                        else:
                            result_string += " | {}: {}".format(field, iip.get(field))
                    if result_string.endswith(','):
                        print(result_string[:-1])
                    else:
                        print(result_string)
                else:
                    print(iip)
        return

    if args.ip:
        iip = mmi.inspect(args.ip)
        if iip:
            if args.raw_results:
                print(json.dumps(iip.raw))
            elif args.pretty_print:
                pprint(iip.raw)
            elif args.fields:
                for field in args.fields:
                    print(iip.get(field))
            else:
                print(iip)
        return
