#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK

import os
import sys
import json
import argparse
import argcomplete
import logging
import coloredlogs

from pprint import pprint
from ip_inspector.config import CONFIG, save_configuration, load_configuration, update_configuration
from ip_inspector import maxmind, tor
from ip_inspector import Inspector, append_to_, remove_from_

from ip_inspector.database import (
    get_db_session,
    get_infrastructure_context_map,
    create_infrastructure_context,
    delete_infrastructure_context,
    get_all_infrastructure_context,
    DEFAULT_INFRASTRUCTURE_CONTEXT_NAME,
    get_blacklists,
    get_whitelists,
)

LOGGER = logging.getLogger("ip-inspector.cli")


def build_parser():
    """Build the CLI Argument parser."""

    parser = argparse.ArgumentParser(description="Inspect IP address metadata for IDR purposes")
    parser.add_argument("-d", "--debug", default=False, action="store_true", help="Turn on debug logging.")
    parser.add_argument(
        "-u", "--update-databases", default=False, action="store_true", help="Update the MaxMind GeoLite2 Databases"
    )
    parser.add_argument(
        "-r", "--json", dest="raw_results", action="store_true", help="return results in their raw json format"
    )
    parser.add_argument("-pp", "--pretty-print", action="store_true", help="Pretty print the raw json results")
    parser.add_argument("-i", "--ip", action="store", help="A single IP address to inspect.")
    parser.add_argument("--print-tor-exits", action="store_true", help="Get tor exist nodes")
    parser.add_argument(
        "-f",
        "--field",
        action="append",
        dest="fields",
        default=[],
        choices=maxmind.FIELDS,
        help="specific fields to return",
    )
    parser.add_argument(
        "-csv", action="store_true", help="print fields as comma seperated with --from-stdin and fields"
    )
    parser.add_argument(
        "--from-stdin", action="store_true", help="Inspect each IP in a list of IP addresses passed to STDIN"
    )
    parser.add_argument(
        "-lk", "--license-key", action="store", help="Set MaxMind Liscense Key (saves to config for future use)"
    )
    parser.add_argument(
        "--update-config",
        action="store",
        help="Path to a JSON config containing updates that should be applied to update or override the existing configuration.",
    )
    help_note = (
        "Write a copy of the existing configuration to the local config path for easily making configuration overrides, "
        "changes, or updates. Edit the local config to meet your needs."
    )
    parser.add_argument("--customize", action="store_true", help=help_note)
    parser.add_argument(
        "--print-tracking-contexts", action="store_true", help="Show existing infrastructure tracking contexts."
    )
    parser.add_argument(
        "--create-tracking-context", action="store", help="Create a new infrastructure tracking context."
    )
    parser.add_argument(
        "--delete-tracking-context", action="store", type=int, help="Delete the infrastructure tracking context by ID."
    )

    default_context_name = CONFIG["default"].get("tracking_context", DEFAULT_INFRASTRUCTURE_CONTEXT_NAME)
    infrastructure_context_map = {}
    with get_db_session() as session:
        infrastructure_context_map = get_infrastructure_context_map(session)
    context_choices = list(infrastructure_context_map.keys())
    parser.add_argument(
        "-c",
        "--context",
        action="store",
        default=default_context_name,
        choices=context_choices,
        help=f"The infrastructure context to work under. default={default_context_name}",
    )
    parser.add_argument(
        "--set-default-context",
        action="store",
        choices=context_choices,
        help="Set the default infrastructure tracking context to work under.",
    )

    subparsers = parser.add_subparsers(dest="command")

    wl_parser = subparsers.add_parser("whitelist", help="For interacting with the IP Network Organization whitelist")
    wl_parser.add_argument("-p", "--print", action="store_true", help="Print the existing whitelist.")

    wl_subparser = wl_parser.add_subparsers(dest="wl_command")
    wl_add_parser = wl_subparser.add_parser("add", help="Append to a whitelist.")
    wl_add_parser.add_argument("-i", "--ip", action="store", help="The IP address to work with.")
    wl_add_parser.add_argument(
        "-t",
        "--whitelist-type",
        action="append",
        default=["ORG"],
        choices=CONFIG["default"]["whitelists"],
        help="The type of metadata from this IP result that should be whitelisted. Can specify multiple times.",
    )
    wl_add_parser.add_argument(
        "-r", "--reference", action="store", default=None, help="A custom reference for the entry."
    )

    wl_remove_parser = wl_subparser.add_parser("remove", help="Remove a whitelist entry.")
    wl_remove_parser.add_argument("-i", "--ip", action="store", help="The IP address to work with.")
    wl_remove_parser.add_argument(
        "-t",
        "--whitelist-type",
        action="append",
        default=["ORG"],
        choices=CONFIG["default"]["whitelists"],
        help="The type of metadata from this IP result that should be removed from the respective whitelist. Can specify multiple times.",
    )
    wl_remove_parser.add_argument(
        "-r",
        "--reference",
        action="store",
        default=None,
        help="Remove all entries where the IP is found as a reference.",
    )

    bl_parser = subparsers.add_parser("blacklist", help="For interacting with the IP Network Organization blacklist.")
    bl_parser.add_argument("-p", "--print", action="store_true", help="Print the existing blacklist.")

    bl_subparser = bl_parser.add_subparsers(dest="bl_command")
    bl_add_parser = bl_subparser.add_parser("add", help="Append to a blacklist.")
    bl_add_parser.add_argument("-i", "--ip", action="store", help="The IP address to work with.")
    bl_add_parser.add_argument(
        "-t",
        "--blacklist-type",
        action="append",
        default=["ORG"],
        choices=CONFIG["default"]["blacklists"],
        help="The type of metadata from this IP result that should be blacklisted. Can specify multiple times.",
    )
    bl_add_parser.add_argument(
        "-r", "--reference", action="store", default=None, help="A custom reference for the entry."
    )

    bl_remove_parser = bl_subparser.add_parser("remove", help="Remove a blacklist entry.")
    bl_remove_parser.add_argument("-i", "--ip", action="store", help="The IP address to work with.")
    bl_remove_parser.add_argument(
        "-t",
        "--blacklist-type",
        action="append",
        default=["ORG"],
        choices=CONFIG["default"]["blacklists"],
        help="The type of metadata from this IP result that should be removed from the respective blacklist. Can specify multiple times.",
    )
    bl_remove_parser.add_argument(
        "-r", "--reference", action="store", default=None, help="Remove entries with this reference."
    )

    argcomplete.autocomplete(parser)
    return parser


def main(args=None):
    """The main CLI entry point."""

    # configure logging
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - [%(levelname)s] %(message)s")
    coloredlogs.install(level="INFO", logger=LOGGER)

    if not args:
        args = sys.argv[1:]

    parser = build_parser()
    args = parser.parse_args(args)

    infrastructure_context_map = {}
    default_context_name = CONFIG["default"].get("tracking_context", DEFAULT_INFRASTRUCTURE_CONTEXT_NAME)
    with get_db_session() as session:
        infrastructure_context_map = get_infrastructure_context_map(session)

    if args.debug:
        coloredlogs.install(level="DEBUG", logger=LOGGER)

    if args.print_tor_exits:
        for EN in tor.ExitNodes().exit_nodes:
            print(EN)
        return True

    ## config options ##
    if args.update_config:
        if not os.path.exists(args.update_config):
            print("That file doesn't exist.")
            return False
        if update_configuration(args.update_config):
            LOGGER.info(f"updated configuration with config items from {args.update_config}")
            return True
        LOGGER.warning(f"could not update configuration.")
        return False

    if args.customize:
        # save will write the existing loaded configuration to the SAVED_CONFIG_PATH
        if save_configuration(CONFIG, config_path="ip_inspector.config.json"):
            print("Wrote the existing configuration to: ip_inspector.config.json")
            print("Make any changes to that configuration file and then supply it to `ip-inspector --config-path`")
            return True
        return False

    if args.license_key:
        data = {}
        data["maxmind"] = {"license_key": args.license_key}
        if not save_configuration(data):
            return False
        LOGGER.info(f"saved license key.")
        # put it in the right place so this session can continue
        CONFIG["maxmind"]["license_key"] = args.license_key

    if args.set_default_context:
        if save_configuration({"default": {"tracking_context": args.set_default_context}}):
            LOGGER.info(f"saved default infrastructure tracking context to '{args.set_default_context}'")
            return True
        LOGGER.error(f"couldn't save default tracking context.")
        return False

    ## InfrastructureContext options ##
    if args.print_tracking_contexts:
        with get_db_session() as session:
            for ic in get_all_infrastructure_context(session):
                print(ic)
        return True

    if args.create_tracking_context:
        with get_db_session() as session:
            result = create_infrastructure_context(session, args.create_tracking_context)
            if not result:
                LOGGER.error(
                    f"failed to create new infrastructure context for tracking by name: {args.create_tracking_context}"
                )
                return False
            LOGGER.info(f"created new infrastructure context: {result}")
            return True

    if args.delete_tracking_context:
        with get_db_session() as session:
            result = delete_infrastructure_context(session, args.delete_tracking_context)
            if not result:
                LOGGER.error(f"failed to delete infrastructure context: {args.delete_tracking_context}")
                return False
            LOGGER.info("deleted infrastructure context.")
            return True

    ## Maxmind ##
    if args.update_databases:
        if not maxmind.update_databases(license_key=CONFIG["maxmind"]["license_key"]):
            return False
        return True

    ## IP Inspection ##
    mmi = Inspector(maxmind_license_key=CONFIG["maxmind"]["license_key"])

    ## Blacklist/Whitelist options ##
    if args.command == "blacklist" or args.command == "whitelist":
        if args.print:
            with get_db_session() as session:
                if args.command == "blacklist":
                    for bl in get_blacklists(session):
                        print(bl)
                    return True
                if args.command == "whitelist":
                    for wl in get_whitelists(session):
                        print(wl)
                    return True

        ip_list = []
        if args.ip:
            ip = args.ip
            if "/" in ip:
                ip = ip[: ip.rfind("/")]
            ip_list.append(ip)

        if args.from_stdin:
            ip_list = [line.strip() for line in sys.stdin]

        if not ip_list:
            LOGGER.info(f"No IP addresses passed, nothing to-do.")

        for ip in ip_list:
            iip = mmi.inspect(ip, infrastructure_context=infrastructure_context_map[args.context])

            if args.command == "blacklist":
                if args.bl_command == "add":
                    result = append_to_(
                        "blacklist",
                        iip,
                        fields=list(set(args.blacklist_type)),
                        context_id=infrastructure_context_map[args.context],
                        reference=args.reference,
                    )
                    if result:
                        LOGGER.info(f"created: {result}")

                elif args.bl_command == "remove":
                    if remove_from_(
                        "blacklist",
                        iip,
                        fields=list(set(args.blacklist_type)),
                        context_id=infrastructure_context_map[args.context],
                        reference=args.reference,
                    ):
                        LOGGER.info(f"successfully removed matching blacklist entries.")
                    else:
                        LOGGER.info(f"no blacklist entries found for removal.")

            if args.command == "whitelist":
                if args.wl_command == "add":
                    result = append_to_(
                        "whitelist",
                        iip,
                        fields=list(set(args.whitelist_type)),
                        context_id=infrastructure_context_map[args.context],
                    )
                    if result:
                        LOGGER.info(f"created: {result}")

                elif args.wl_command == "remove":
                    if remove_from_(
                        "whitelist",
                        iip,
                        fields=list(set(args.whitelist_type)),
                        context_id=infrastructure_context_map[args.context],
                        reference=args.reference,
                    ):
                        LOGGER.info(f"successfully removed matching whitelist entries.")
                    else:
                        LOGGER.info(f"no whitelist entries found for removal.")

        return

    ## IP Inspection only options ##
    if args.from_stdin:
        if args.fields and args.csv:
            header = "IP/Network," + ",".join(args.fields)
            print(header)
        iplist = [line.strip() for line in sys.stdin]
        for ip in iplist:
            iip = mmi.inspect(ip, infrastructure_context=infrastructure_context_map[args.context])
            if iip:
                if args.raw_results:
                    print(json.dumps(iip.to_dict()))
                elif args.pretty_print:
                    pprint(iip.to_dict())
                elif args.fields:
                    result_string = f"--> {iip.network_value_passed if iip.network_value_passed else iip.ip}"
                    if args.csv:
                        result_string = f"{iip.network_value_passed if iip.network_value_passed else iip.ip},"
                    for field in args.fields:
                        if args.csv:
                            result_string += '"{}",'.format(iip.get(field))
                        else:
                            result_string += " | {}: {}".format(field, iip.get(field))
                    if result_string.endswith(","):
                        print(result_string[:-1])
                    else:
                        print(result_string)
                else:
                    print(iip)
        return

    if args.ip:
        iip = mmi.inspect(args.ip, infrastructure_context=infrastructure_context_map[args.context])
        if iip:
            if args.raw_results:
                print(json.dumps(iip.to_dict()))
            elif args.pretty_print:
                pprint(iip.to_dict())
            elif args.fields:
                for field in args.fields:
                    print(iip.get(field))
            else:
                print(iip)
            return True
        return False

    return
