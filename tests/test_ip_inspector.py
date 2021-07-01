import os
import sys
import pytest

from tests import *


def test_version():
    from ip_inspector import __version__

    assert __version__ == "0.1.0"


def test_inspector_contruction():
    from ip_inspector import Inspector, maxmind, tor

    ipi = Inspector(maxmind_license_key=get_real_license_key())
    assert isinstance(ipi, Inspector)
    assert isinstance(ipi.mmc, maxmind.Client)
    assert isinstance(ipi.tor_exits, tor.ExitNodes)


def test_inspector_function(test_database):
    from ip_inspector import Inspector, Inspected_IP

    ipi = Inspector(maxmind_license_key=get_real_license_key())

    inspected_ip = ipi.inspect("8.8.8.8")
    assert isinstance(inspected_ip, Inspected_IP)
    assert isinstance(ipi.get("8.8.8.8"), Inspected_IP)

    # context does not exist but the inspector shouldn't care
    inspected_ip = ipi.inspect("8.8.8.8", infrastructure_context=20)
    assert isinstance(inspected_ip, Inspected_IP)
    inspected_ip = ipi.inspect("8.8.8.8", infrastructure_context="faketest")
    assert isinstance(inspected_ip, Inspected_IP)
    # context does not exist but the inspector shouldn't care
    inspected_ip = ipi.get("8.8.8.8", infrastructure_context=20)
    assert isinstance(inspected_ip, Inspected_IP)
    inspected_ip = ipi.get("8.8.8.8", infrastructure_context="faketest")
    assert isinstance(inspected_ip, Inspected_IP)


def test_inspected_ip(test_database):
    from ip_inspector import Inspector, Inspected_IP

    ip = "8.8.8.8"
    inspector = Inspector(maxmind_license_key=get_real_license_key())
    # manually construct by access inspectors maxmind readers
    iip = Inspected_IP(inspector.mmc.asn(ip), inspector.mmc.city(ip), inspector.mmc.country(ip))
    # should be False as the Inspector does the inspecting
    assert iip.is_blacklisted == False
    assert iip.is_whitelisted == False
    assert not iip.blacklisted_fields
    assert not iip.whitelisted_fields
    assert iip.get("ORG") == "GOOGLE"
    assert iip.get("ASN") == 15169
    assert iip.ip == ip

    from ip_inspector.database import check_whitelist, check_blacklist, get_db_session

    with get_db_session() as session:
        blacklist_results = check_blacklist(session, org=iip.get("ORG"))
        # do not whitelist with anything other than a WhitelistEntry
    with pytest.raises(AssertionError):
        iip.set_whitelist(blacklist_results)
    assert iip.set_blacklist(blacklist_results) == True
    # there are two separate entries with GOOGLE blacklisted
    assert len(iip._blacklist_reasons) == 2
    assert iip.blacklisted_fields == ["ORG"]
    assert iip.is_blacklisted == True
    assert iip.is_whitelisted == False
    # don't whitelist what is blacklisted
    assert iip.set_whitelist(blacklist_results) == False
    # assert string output looks correct
    # ORG: GOOGLE (!BLACKLISTED!)
    assert "ORG: GOOGLE (!BLACKLISTED!)" == f"ORG: {iip.get('ORG')} {iip._blacklist_str}"
    assert f"ORG: {iip.get('ORG')} {iip._blacklist_str}" in str(iip)
    iip.remove_blacklist()
    assert iip.is_blacklisted == False

    with get_db_session() as session:
        whitelist_results = check_whitelist(session, context=700, org=iip.get("ORG"))
    with pytest.raises(AssertionError):
        iip.set_blacklist(whitelist_results)
    assert iip.set_whitelist(whitelist_results) == True
    assert iip.is_whitelisted == True
    assert iip.is_blacklisted == False
    assert "ORG: GOOGLE (whitelisted)" == f"ORG: {iip.get('ORG')} {iip._whitelist_str}"
    assert f"ORG: {iip.get('ORG')} {iip._whitelist_str}" in str(iip)
    assert iip.whitelisted_fields == ["ORG"]
    iip.remove_whitelist()
    assert iip.is_whitelisted == False
    assert iip.is_blacklisted == False
    assert iip.refresh() == True
    assert iip.is_blacklisted == True


def test_append_to_(fresh_database):
    from ip_inspector import append_to_, BlacklistEntry, WhitelistEntry

    iip = get_inspected_ip()
    with pytest.raises(ValueError):
        append_to_("blah", iip, fields=["ORG"])

    iip._whitelisted = True
    assert append_to_("blacklist", iip, fields=["ORG"]) == False
    iip._whitelisted = False
    iip._blacklisted = True
    entry = append_to_("blacklist", iip, fields=["ORG"])
    assert isinstance(entry, BlacklistEntry)
    # NOTE: iip.refresh() is called if an entry is appended to update iip with it's new status
    # entry like this already exists, so nothing to do and None
    assert append_to_("blacklist", iip, fields=["ORG"]) is None
    assert append_to_("whitelist", iip, fields=["ORG"]) is False
    # hmm
    iip.remove_blacklist()
    # append_to_ should refresh iip and catch that it hits on the blacklist
    assert append_to_("whitelist", iip, fields=["ORG"]) is False
    # NOTE: duplicate field values accross entries are allowed and seen as flexibility.
    assert isinstance(append_to_("blacklist", iip, fields=["ASN"]), BlacklistEntry)
    # So this should also work...
    result = append_to_("blacklist", iip, fields=["ASN", "ORG", "Country"], context_id=1)
    assert isinstance(result, BlacklistEntry)
    # but, the only field that's not None should be Country (because previous entries already have the other field values)
    assert result.country == iip.get("Country") and result.org is None and result.asn is None
    # For the sake of avoiding ambiguous confusion, False if iip._infrastructure_context does not match
    assert iip._infrastructure_context == 1
    assert append_to_("blacklist", iip, fields=["ORG"], context_id=5) == False


def test_remove_from_(test_database):
    from ip_inspector import remove_from_
    from ip_inspector.database import BlacklistEntry, WhitelistEntry, get_whitelists, get_blacklists, get_db_session

    iip = get_inspected_ip()
    with pytest.raises(ValueError):
        remove_from_("blah", iip, fields=["ORG"])
    with get_db_session() as session:
        assert len(get_blacklists(session)) == 5
    assert remove_from_("blacklist", iip, fields=["asdf"]) == False
    assert remove_from_("blacklist", iip, fields=["ORG"], context_id=5) == False
    assert remove_from_("blacklist", iip, fields=["ORG"], context_id=1) == None
    iip._infrastructure_context = 2
    assert remove_from_("blacklist", iip, fields=["ORG"], context_id=2) == True
    with get_db_session() as session:
        assert len(get_blacklists(session)) == 3
        assert len(get_whitelists(session)) == 5
    assert remove_from_("whitelist", iip, fields=["ASN"], context_id=2) == True
    with get_db_session() as session:
        assert len(get_whitelists(session)) == 4
    iip._infrastructure_context = 700
    assert remove_from_("whitelist", iip, fields=["ORG"], context_id=700, reference=iip.ip) == True
    with get_db_session() as session:
        assert len(get_whitelists(session)) == 3
