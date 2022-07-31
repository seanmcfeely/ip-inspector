import os
import sys
import pytest

from tests import *

from ip_inspector.database import get_db_session


def test_create_infrastructure_context(fresh_database):
    from ip_inspector.database import create_infrastructure_context, InfrastructureContext

    with get_db_session() as session:
        icontext = create_infrastructure_context(session, "test_context")
    assert isinstance(icontext, InfrastructureContext)
    assert icontext.name == "test_context"
    assert icontext.id == 1
    # should not be created
    with get_db_session() as session:
        result = create_infrastructure_context(session, "test_context")
    assert result is None


def test_delete_infrastructure_context(test_database):
    from ip_inspector.database import delete_infrastructure_context

    with get_db_session() as session:
        # ensure we refuse to delete the "default" context ID #1
        assert delete_infrastructure_context(session, 1) == None
        # does not exist, should be False
        assert delete_infrastructure_context(session, -1) == False
        # True
        assert delete_infrastructure_context(session, 2) == True


def test_get_infrastructure_context_map(test_database):
    from ip_inspector.database import get_infrastructure_context_map

    with get_db_session() as session:
        context_map = get_infrastructure_context_map(session)
        assert isinstance(context_map, dict)
        assert context_map["test_default_context"] == 1


def test_get_all_infrastructure_context(test_database):
    from ip_inspector.database import get_all_infrastructure_context

    with get_db_session() as session:
        assert isinstance(get_all_infrastructure_context(session), list)


def test_get_infrastructure_context_by_name(test_database):
    from ip_inspector.database import get_infrastructure_context_by_name, InfrastructureContext

    with get_db_session() as session:
        result = get_infrastructure_context_by_name(session, "test_another_context")
        assert isinstance(result, InfrastructureContext)


def test_get_infrastructure_context_by_id(test_database):
    from ip_inspector.database import get_infrastructure_context_by_id, InfrastructureContext

    with get_db_session() as session:
        result = get_infrastructure_context_by_id(session, 2)
        assert isinstance(result, InfrastructureContext)


def test_append_to_blacklist(fresh_database):
    from ip_inspector.database import append_to_blacklist, BlacklistEntry

    iip = get_inspected_ip()
    with get_db_session() as session:
        bl_entry = append_to_blacklist(
            session,
            context=1,
            org=iip.get("ORG"),
            asn=iip.get("ASN"),
            country=iip.get("Country"),
            reference="for testing",
        )
        assert isinstance(bl_entry, BlacklistEntry)
        entry = append_to_blacklist(
            session, context=1, org="float stack", asn=54, country="Canada", reference="Cartoon Network"
        )
        assert entry.id == 2
        assert entry.infrastructure_id == 1
        assert entry.org == "float stack"
        assert entry.asn == 54
        assert entry.country == "Canada"
        assert entry.reference == "Cartoon Network"
        # have to supply one of org, asn, country
        assert append_to_blacklist(session, context=1, reference="ha!") is False
        # NOTE: I've made a decision not to check that the context ID exists in this function
        # so the entry is created even if the InfrastructureContext does not exist.
        assert isinstance(append_to_blacklist(session, context=700, org="ha!"), BlacklistEntry)


def test_append_to_whitelist(fresh_database):
    from ip_inspector.database import append_to_whitelist, WhitelistEntry

    iip = get_inspected_ip()
    with get_db_session() as session:
        bl_entry = append_to_whitelist(
            session,
            context=1,
            org=iip.get("ORG"),
            asn=iip.get("ASN"),
            country=iip.get("Country"),
            reference="for testing",
        )
        assert isinstance(bl_entry, WhitelistEntry)
        entry = append_to_whitelist(
            session, context=1, org="float stack", asn=54, country="Canada", reference="Cartoon Network"
        )
        assert entry.id == 2
        assert entry.infrastructure_id == 1
        assert entry.org == "float stack"
        assert entry.asn == 54
        assert entry.country == "Canada"
        assert entry.reference == "Cartoon Network"
        # have to supply one of org, asn, country
        assert append_to_whitelist(session, context=1, reference="ha!") is False
        # NOTE: I've made a decision not to check that the context ID exists in this function
        # so the entry is created even if the InfrastructureContext does not exist.
        assert isinstance(append_to_whitelist(session, context=700, org="ha!"), WhitelistEntry)


def test_get_blacklists(test_database):
    from ip_inspector.database import get_blacklists, BlacklistEntry

    with get_db_session() as session:
        results = get_blacklists(session)
    assert isinstance(results, list)
    assert isinstance(results[0], BlacklistEntry)


def test_blacklist_to_dict(test_database):
    from ip_inspector.database import BlacklistEntry

    with get_db_session() as session:
        entry = session.query(BlacklistEntry).get(1)
        result = entry.to_dict()
        assert isinstance(result, dict)
        keys = ["id", "entry_type", "infrastructure_context_id", "org", "asn", "country", "insert_date", "reference"]
        assert keys == list(result.keys())
        assert result["reference"] == "SpaceJam Network"


def test_whitelist_to_dict(test_database):
    from ip_inspector.database import WhitelistEntry

    with get_db_session() as session:
        entry = session.query(WhitelistEntry).get(1)
        result = entry.to_dict()
        assert isinstance(result, dict)
        keys = ["id", "entry_type", "infrastructure_context_id", "org", "asn", "country", "insert_date", "reference"]
        assert keys == list(result.keys())
        assert result["reference"] == "Cartoon Network"


def test_get_whitelist(test_database):
    from ip_inspector.database import get_whitelists, WhitelistEntry

    with get_db_session() as session:
        results = get_whitelists(session)
    assert isinstance(results, list)
    assert isinstance(results[0], WhitelistEntry)


def test_remove_from_blacklist(test_database):
    from ip_inspector.database import remove_from_blacklist, get_blacklists

    with get_db_session() as session:
        assert len(get_blacklists(session)) == 5
        # should be False
        assert remove_from_blacklist(session, context="fake") == False
        assert remove_from_blacklist(session, context=1) == False
        # should be False, fake does not exist and context names are validated
        assert remove_from_blacklist(session, context="fake", org="test") == False
        # does not exist - None
        assert remove_from_blacklist(session, context=2, asn=899, org="fasd") == None
        # org on blacklist but context ID does not exit, and it not validated. So None instead of False.
        assert remove_from_blacklist(session, context=50, org="G00GLE") == None
        # should delete two entries that have org=="G00GLE"
        assert remove_from_blacklist(session, context=2, org="GOOGLE", reference="test") == True
        assert len(get_blacklists(session)) == 3
        assert remove_from_blacklist(session, context=2, org="G00GLE") == True
        assert len(get_blacklists(session)) == 2
        assert remove_from_blacklist(session, context=700, reference="test700") == True
        assert len(get_blacklists(session)) == 1
        assert remove_from_blacklist(session, context=700, country="United States") == None
        assert remove_from_blacklist(session, context=1, country="United States") == True
        assert len(get_blacklists(session)) == 0


def test_remove_from_whitelist(test_database):
    from ip_inspector.database import remove_from_whitelist, get_whitelists

    with get_db_session() as session:
        assert len(get_whitelists(session)) == 5
        # should be False
        assert remove_from_whitelist(session, context="fake") == False
        assert remove_from_whitelist(session, context=1) == False
        # should be False, fake does not exist and context names are validated
        assert remove_from_whitelist(session, context="fake", org="test") == False
        # does not exist - None
        assert remove_from_whitelist(session, context=2, asn=899, org="fasd") == None
        # org on whitelist but context ID does not exit, and it not validated. So None instead of False.
        assert remove_from_whitelist(session, context=50, org="G00GLE") == None
        # remove 2
        assert remove_from_whitelist(session, context=2, reference="8.8.8.8") == True
        assert len(get_whitelists(session)) == 3
        assert remove_from_whitelist(session, context=2, org="Microsoft") == True
        assert len(get_whitelists(session)) == 2
        assert remove_from_whitelist(session, context=700, org="GOOGLE") == True
        assert len(get_whitelists(session)) == 1
        assert remove_from_whitelist(session, context=700, country="United States") == None
        assert remove_from_whitelist(session, context=1, country="Canada") == True
        assert len(get_whitelists(session)) == 0


def test_check_blacklist(test_database):
    from ip_inspector.database import check_blacklist, BlacklistEntry

    with get_db_session() as session:
        # nothing begets nothing
        result = check_blacklist(session)
        assert result == []
        result = check_blacklist(session, org="GOOGLE")
        assert len(result) == 2
        assert isinstance(result[0], BlacklistEntry)
        assert result[0].infrastructure_id == 2
        result = check_blacklist(session, org="G00GLE")
        assert len(result) == 1
        assert result[0].reference is None
        result = check_blacklist(session, context=1, asn=55)
        assert len(result) == 1
        assert result[0].org == "float stack void"
        # nothing still begets nothing
        assert check_blacklist(session, context=1) == []


def test_check_whitelist(test_database):
    from ip_inspector.database import check_whitelist, WhitelistEntry

    with get_db_session() as session:
        # nothing begets nothing
        result = check_whitelist(session)
        assert result is False
        result = check_whitelist(session, org="GOOGLE")
        assert len(result) == 2
        assert isinstance(result[0], WhitelistEntry)
        assert result[0].infrastructure_id == 2
        assert result[1].infrastructure_id == 700
        result = check_whitelist(session, org="G00GLE")
        assert not result
        result = check_whitelist(session, context=1, asn=15169)
        assert len(result) == 0
        result = check_whitelist(session, context=2, asn=15169)
        assert len(result) == 1
        assert result[0].reference == "8.8.8.8"
        # nothing still begets nothing
        assert check_whitelist(session, context=1) is False
