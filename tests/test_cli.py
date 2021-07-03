import os
import sys
import pytest

from tests import *


def test_main_basic_options(test_database):
    from ip_inspector.cli import main

    # just test some basics
    assert main(["-d"]) == None
    # assert main(["--print-tor-exits"]) is True
    assert main(["--update-config", "fake_path"]) is False
    assert main(["--customize"]) is True
    assert os.path.exists("ip_inspector.config.json") is True
    assert main(["--update-config", "ip_inspector.config.json"]) is True
    assert os.remove("ip_inspector.config.json") is None
    # do nothing without args.ip
    assert main(["-f", "ORG", "-pp", "-csv", "-r"]) == None
    # does not have license key, should return False
    assert main(["-u"]) == False

    license_key = get_real_license_key()
    # does not return so more argument executions can continue
    # so None if no other options are set
    assert main(["-lk", f"{license_key}"]) == None
    assert main(["--set-default-context", "test_another_context"]) == True
    assert main(["-u"]) == True


def test_main_context_management(test_database):
    from ip_inspector.cli import main

    assert main(["--create-tracking-context", "test_context_creation"]) == True
    assert main(["--delete-tracking-context", "2"]) == True
    assert main(["--delete-tracking-context", "9001"]) == False
    # don't delete default context ID
    assert main(["--delete-tracking-context", "1"]) == False
    assert main(["--print-tracking-contexts"]) == True


def test_main_inspection(test_database, capsys):
    from ip_inspector.cli import main

    ipi = get_inspected_ip()
    assert main(["-i", ipi.ip, "-c", "test_default_context"]) == True
    captured = capsys.readouterr()
    assert "GOOGLE (!BLACKLISTED!)" in captured.out
    assert main(["-i", ipi.ip, "-c", "test_default_context", "-f", "ORG"]) == True
    captured = capsys.readouterr()
    assert "GOOGLE (!BLACKLISTED!)\n" == captured.out


def test_main_json_output(test_database, capsys):
    import json
    from ip_inspector.cli import main

    ipi = get_inspected_ip()
    assert main(["-i", ipi.ip, "-c", "test_default_context", "--json"]) == True
    captured = capsys.readouterr()
    assert isinstance(json.loads(captured.out), dict)


def test_main_listing_functions(test_database, capsys):
    from ip_inspector.cli import main

    # printing
    assert main(["blacklist", "-p"]) == True
    captured = capsys.readouterr()
    listing = [entry for entry in captured.out.split("\n") if entry]
    assert len(listing) == 5
    assert "float stack void" in listing[0]
    assert main(["whitelist", "-p"]) == True
    captured = capsys.readouterr()
    listing = [entry for entry in captured.out.split("\n") if entry]
    assert len(listing) == 5
    assert "float stack" in listing[0]

    # NOTE: with support for from-stdin, all of these will return None
    # append &remove complexities
    ipi = get_inspected_ip()
    assert main(["-c", "test_another_context", "blacklist", "remove", "-i", ipi.ip]) == None
    captured = capsys.readouterr()
    assert "successfully removed matching blacklist entries." in captured.err
    assert main(["-c", "test_another_context", "whitelist", "remove", "-i", ipi.ip]) == None
    captured = capsys.readouterr()
    assert "successfully removed matching whitelist entries." in captured.err

    # failed because country="United States" entry under context
    assert main(["-c", "test_default_context", "blacklist", "add", "-i", ipi.ip]) == None
    captured = capsys.readouterr()
    assert main(["-c", "test_default_context", "blacklist", "remove", "-i", ipi.ip, "-t", "Country"]) == None
    captured = capsys.readouterr()
    assert "successfully removed matching blacklist entries." in captured.err
    assert main(["-c", "test_default_context", "blacklist", "add", "-i", ipi.ip]) == None
    captured = capsys.readouterr()
    assert "created: Blacklist" in captured.err
    assert main(["-c", "test_default_context", "blacklist", "remove", "-i", ipi.ip]) == None
    captured = capsys.readouterr()
    assert main(["-c", "test_default_context", "whitelist", "add", "-i", ipi.ip, "-t", "ASN"]) == None
    captured = capsys.readouterr()
    assert "created: Whitelist" in captured.err
