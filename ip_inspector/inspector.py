import os
import shutil
import logging

from typing import Union, List

from ip_inspector.config import CONFIG, WORK_DIR
from ip_inspector import maxmind, tor
from ip_inspector.database import (
    get_db_session,
    get_infrastructure_context_map,
    append_to_blacklist,
    append_to_whitelist,
    remove_from_blacklist,
    remove_from_whitelist,
    check_blacklist,
    check_whitelist,
    DEFAULT_INFRASTRUCTURE_CONTEXT_ID,
    BlacklistEntry,
    WhitelistEntry,
)

LOGGER = logging.getLogger("ip-inspector.inspector")


class Inspected_IP(maxmind.MaxMind_IP):
    """IP address enriched with MaxMind and any InfrastructureContext tracking.

    Attributes:
        asn_result: Result of MaxMind ASN DB Reader query.
        city_result: Result of MaxMind City DB Reader query.
        country_result: Result of MaxMind Country DB Reader query.
        tor_exit_node: True if a known tor exit node. eh.
    """

    def __init__(
        self,
        asn_result,
        city_result,
        country_result,
        tor_exit_node=False,
        _infrastructure_context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID,
    ):
        super().__init__(asn_result, city_result, country_result)
        self._blacklist_str = "(!BLACKLISTED!)"
        self._whitelist_str = "(whitelisted)"
        self._blacklisted = False
        self._blacklist_reasons = []
        self._blacklisted_fields = []
        self._whitelisted = False
        self._whitelist_reasons = []
        self._whitelisted_fields = []
        self.is_tor = tor_exit_node
        # expand the map
        if self.is_tor:
            self.map["TOR"] = self.is_tor
        self._infrastructure_context = _infrastructure_context

    def set_blacklist(self, blacklist_results):
        if self.is_whitelisted:
            # XXX has to be under the same context
            LOGGER.error(f"can not blacklist: {self.ip} has whitelist hits on these fields: {self.blacklisted_fields}")
            return False
        assert isinstance(blacklist_results, list)
        assert isinstance(blacklist_results[0], BlacklistEntry)
        self._blacklisted = True
        # store a copy of the reasons
        for bl_entry in blacklist_results:
            # record unique blacklisted fields
            self._blacklisted_fields.extend(bl_entry.blacklisted_fields)
            self._blacklist_reasons.append(bl_entry.to_dict())
        return True

    def set_whitelist(self, whitelist_results):  # XXX db model update it
        if self.is_blacklisted:
            LOGGER.error(f"can not whitelist: {self.ip} has blacklist hits on these fields: {self.blacklisted_fields}")
            return False
        assert isinstance(whitelist_results, list)
        assert isinstance(whitelist_results[0], WhitelistEntry)
        self._whitelisted = True
        # store a copy of the reasons
        for wl_entry in whitelist_results:
            # record unique whitelisted fields
            self._whitelisted_fields.extend(list(set(wl_entry.whitelisted_fields)))
            self._whitelist_reasons.append(wl_entry.to_dict())
        return True

    def remove_blacklist(self):
        self._blacklisted = False
        self._blacklist_reasons = []
        self._blacklisted_fields = []

    def remove_whitelist(self):
        self._whitelisted = False
        self._whitelist_reasons = []
        self._whitelisted_fields = []

    def refresh(self):
        with get_db_session() as session:
            blacklist_results = check_blacklist(
                session,
                context=self._infrastructure_context,
                org=self.get("ORG"),
                asn=self.get("ASN"),
                country=self.get("Country"),
            )
            if blacklist_results:
                self.set_blacklist(blacklist_results)
                return True
            whitelist_results = check_whitelist(
                session,
                context=self._infrastructure_context,
                org=self.get("ORG"),
                asn=self.get("ASN"),
                country=self.get("Country"),
            )
            if whitelist_results:
                self.set_whitelist(whitelist_results)
        return True

    @property
    def is_whitelisted(self):
        return self._whitelisted

    @property
    def is_blacklisted(self):
        return self._blacklisted

    @property
    def blacklisted_fields(self):
        # return list of fields that point to blacklisted values
        return list(set(self._blacklisted_fields))

    @property
    def whitelisted_fields(self):
        # return list of fields that point to blacklisted values
        return list(set(self._whitelisted_fields))

    def __str__(self):
        txt = "\t--------------------\n"
        for field in self.map:
            if field == "IP" and self.is_tor:
                txt += f"\t{field}: {self.get(field)} (TOR EXIT)\n"
            elif self.get(field):
                if field in self.blacklisted_fields:
                    txt += f"\t{field}: {self.get(field)} {self._blacklist_str}\n"
                elif field in self.whitelisted_fields:
                    txt += f"\t{field}: {self.get(field)} {self._whitelist_str}\n"
                else:
                    txt += f"\t{field}: {self.get(field)}\n"
            else:
                txt += f"\t{field}: \n"
        return txt


class Inspector:
    """Internet Protocol metadata InfrastructureContext inspector.

       A wrapper around the maxmind client that uses the MaxMind GeoLite2 databases to
       get metadata on given IPv4/IPv6 observables and then checks popular metadata field values
       against a database that tracks blacklists and whitelist values.

    Attributes:
        maxmind_license_key: A MaxMind license key.
        tor_exits: An optional list of tor_exit nodes. Eh.
    """

    # change to accept maxmind license key instead?
    # def __init__(self, mmc: maxmind.Client=maxmind.Client(),tor_exits: Union[tor.ExitNodes, None]=tor.ExitNodes() or None):
    def __init__(self, maxmind_license_key: str, tor_exits: Union[tor.ExitNodes, None] = tor.ExitNodes() or None):
        self.mmc = maxmind.Client(license_key=maxmind_license_key)
        self.tor_exits = tor_exits

    def inspect(self, ip, infrastructure_context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID):
        """Get IP metadata and enrich with InfrastructureContext Blacklist/Whitelist hits.

        Args:
            ip: IPv4 or IPv6
            infrastructure_context: name or ID of an InfrastructureContext to work under.

        Returns:
            An Inspected_IP object.
        """
        try:
            IIP = Inspected_IP(
                self.mmc.asn(ip),
                self.mmc.city(ip),
                self.mmc.country(ip),
                tor_exit_node=self.tor_exits.is_exit_node(ip),
                _infrastructure_context=infrastructure_context,
            )
            with get_db_session() as session:
                blacklist_results = check_blacklist(
                    session,
                    context=infrastructure_context,
                    org=IIP.get("ORG"),
                    asn=IIP.get("ASN"),
                    country=IIP.get("Country"),
                )
                if blacklist_results:
                    IIP.set_blacklist(blacklist_results)
                # both should not happen
                whitelist_results = check_whitelist(
                    session,
                    context=infrastructure_context,
                    org=IIP.get("ORG"),
                    asn=IIP.get("ASN"),
                    country=IIP.get("Country"),
                )
                if whitelist_results:
                    IIP.set_whitelist(whitelist_results)

            return IIP

        except Exception as e:
            LOGGER.warning(f"Problem inspecting ip={ip} : {e}")
            return None

    def get(self, ip, infrastructure_context: Union[str, int] = DEFAULT_INFRASTRUCTURE_CONTEXT_ID):
        """Get IP metadata and enrich with InfrastructureContext Blacklist/Whitelist hits.

        For convienice switching between Inspector and MaxMind Client

        Args:
            ip: IPv4 or IPv6
            infrastructure_context: name or ID of an InfrastructureContext to work under.

        Returns:
            An Inspected_IP object.
        """
        return self.inspect(ip, infrastructure_context=infrastructure_context)


def append_to_(
    list_type: Union["blacklist", "whitelist"],
    iip: Inspected_IP,
    fields: List,
    context_id: int = 1,
    reference: str = None,
):
    """Append a new ip whitelist OR blacklist entry.

    Args:
        list_type: The type of list to remove from.
        iip: the Inspected_IP
        fields: List of Inspected_IP fields to reference the values of.
        context_id: The ID of an InfrastructureContext to work under.
        reference: The value of a WhitelistEntry OR BlacklistEntry.

    Returns:
        True on success.
    """
    if list_type not in ["blacklist", "whitelist"]:
        raise ValueError(f"{list_type} is not valid. Must be one of [blacklist, whitelist]")
    # Don't allow whitelisting and blacklisting under the same context
    # Just in case this Inspected_IP is not up-to-date, we spend the cycles to refresh() it.
    iip.refresh()
    if context_id != iip._infrastructure_context:
        LOGGER.error(f"{iip.ip} inspected under different infrastructure context")
        return False
    if list_type == "blacklist" and iip.is_whitelisted:
        LOGGER.error(f"{iip.ip} has whitelist hits.")
        return False
    if list_type == "whitelist" and iip.is_blacklisted:
        LOGGER.error(f"{iip.ip} has blacklist hits.")
        return False
    # NOTE: Here is the only place we check to avoide adding truly duplicative entries.
    # NOTE: However, duplicate field values accross entries are allowed and seen as flexibility.
    if list_type == "blacklist" and iip.is_blacklisted:
        for field in fields.copy():
            if field in iip.blacklisted_fields:
                LOGGER.info(f"{field} already blacklisted")
                fields.remove(field)
    if list_type == "whitelist" and iip.is_whitelisted:
        for field in fields.copy():
            if field in iip.whitelisted_fields:
                LOGGER.info(f"{field} already whitelisted")
                fields.remove(field)
    if not fields:
        LOGGER.info("nothing to update.")
        return None
    # first, set field values if the field was passed
    org = asn = country = None
    for field in fields:
        if field == "ORG":
            org = iip.get(field)
        if field == "ASN":
            asn = iip.get(field)
        if field == "Country":
            country = iip.get(field)
    if reference is None:
        reference = iip.ip
    with get_db_session() as session:
        if list_type == "blacklist":
            entry = append_to_blacklist(
                session, context=context_id, org=org, asn=asn, country=country, reference=reference
            )
            if entry:
                iip.refresh()
            return entry
        elif list_type == "whitelist":
            entry = append_to_whitelist(
                session, context=context_id, org=org, asn=asn, country=country, reference=reference
            )
            if entry:
                iip.refresh()
            return entry


def remove_from_(
    list_type: Union["blacklist", "whitelist"],
    iip: Inspected_IP,
    fields: List,
    context_id: int = 1,
    reference: str = None,
):
    """Remove ip context from a whitelist OR blacklist.

    Args:
        list_type: The type of list to remove from.
        iip: the Inspected_IP
        fields: List of Inspected_IP fields to reference the values of.
        context_id: The ID of an InfrastructureContext to work under.
        reference: The value of a WhitelistEntry OR BlacklistEntry.

    Returns:
        True on success.
    """
    if list_type not in ["blacklist", "whitelist"]:
        raise ValueError(f"{list_type} is not valid. Must be one of [blacklist, whitelist]")
    # make sure Inspected_IP up-to-date
    iip.refresh()
    if context_id != iip._infrastructure_context:
        LOGGER.error(f"{iip.ip} inspected under different infrastructure context")
        return False
    org = asn = country = None
    for field in fields:
        if field == "ORG":
            org = iip.get(field)
        if field == "ASN":
            asn = iip.get(field)
        if field == "Country":
            country = iip.get(field)

    with get_db_session() as session:
        if list_type == "blacklist":
            result = remove_from_blacklist(
                session, context=context_id, org=org, asn=asn, country=country, reference=reference
            )
            if result:
                iip.refresh()
            return result
        elif list_type == "whitelist":
            result = remove_from_whitelist(
                session, context=context_id, org=org, asn=asn, country=country, reference=reference
            )
            if result:
                iip.refresh()
            return result
