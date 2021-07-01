# IP Inspector

IP inspector is an IPv4 and IPv6 address metadata (ASN, geo-location, Organization, etc.) enricher and metadata tracking tool. Use it on the command line and leverage it as a library.

## TL;DR

You can feed `ip-inspector` IP addresses from contextual sources and track that infrastructure according to tracking context you're interested in, or you can use it to look up what country an IP address is associated to.

### Main Functionality
  1. Getting IP metadata
  2. Tracking internet infrastructure over as many different contexts as you desire.

### Example Use Cases

- You want to detect anomalies in user authentications. You can use this tool to baseline the internet infrastructure users authenticate from on a per user or per authentication tenant basis.
- You want to track recon you see on your perimeter. You can blacklist identified recon networks and see if those networks show up elsewhere, like your user authentication logs.
- You want to track the infrastructure that's hosting the URLs your users (one-to-many) receive for known bad infrastructure and/or anomalies.

### What to know

`ip-inspector` depends on the free [GeoLite2 databases](https://dev.maxmind.com/geoip/geoip2/geolite2/) provided by [MaxMind](https://www.maxmind.com/en/home) (thank you, MaxMind!). 

You can register for a free MaxMind license key here: [https://www.maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup).

See [this page](docs/how-to/update-maxmind-databases.md) for help on how to keep your databases updated.

## Install

```
pip install ip-inspector
```

## Quick CLI Intro

Here are some quick examples of how to using `ip-inspector` on the CLI.

> NOTE: The following examples assume you already have the [MaxMind GeoLite2 databases](docs/how-to/update-maxmind-databases.md).

### Look up a single IP address:

Use the `-i` option, example: `ip-inspector -i 8.8.8.8`

```console
$  ip-inspector -i 8.8.8.8
	--------------------
	IP: 8.8.8.8
	ASN: 15169
	ORG: GOOGLE
	Continent: North America
	Country: United States
	Region: 
	City: 
	Time Zone: America/Chicago
	Latitude: 37.751
	Longitude: -97.822
	Accuracy Radius: 1000
```

#### Getting Specific Fields

```console
$ ip-inspector -i 8.8.8.8 -f ASN -f ORG
15169
GOOGLE
```

#### Returning JSON

`ip-inspector -i 8.8.8.8 --json`

```console
$ ip-inspector -i 8.8.8.8 --json | jq '.asn'
{
  "autonomous_system_number": 15169,
  "autonomous_system_organization": "GOOGLE",
  "ip_address": "8.8.8.8",
  "prefix_len": 24
}
```
### Looking up multiple IP addresses

Here we pipe a list of IP addresses to `ip-inspector` and we specify certain fields we want `ip-inspector` to return. When specifying fields, the output will be organized single lines for easier command-line-fu.

```console
$ echo "208.80.153.224" > interesting.ip.list
$ echo "8.8.8.8" >> interesting.ip.list 
$ 
$ cat interesting.ip.list | ip-inspector --from-stdin -f ORG -f ASN
--> 208.80.153.224 | ORG: WIKIMEDIA | ASN: 14907
--> 8.8.8.8 | ORG: GOOGLE | ASN: 15169
```

Whereas, not specifying fields keeps the standard behavior: 

```console
$ cat interesting.ip.list | ip-inspector --from-stdin 
	--------------------
	IP: 208.80.153.224
	ASN: 14907
	ORG: WIKIMEDIA
	Continent: North America
	Country: United States
	Region: 
	City: 
	Time Zone: America/Chicago
	Latitude: 37.751
	Longitude: -97.822
	Accuracy Radius: 1000

	--------------------
	IP: 8.8.8.8
	ASN: 15169
	ORG: GOOGLE
	Continent: North America
	Country: United States
	Region: 
	City: 
	Time Zone: America/Chicago
	Latitude: 37.751
	Longitude: -97.822
	Accuracy Radius: 1000
```

### Whitelists and Blacklists

#### List Additions

The following will add this Organization and ASN to the default whitelist.

`ip-inspector whitelist add 8.8.8.8 -t ORG -t ASN`

```console
$ ip-inspector whitelist add 8.8.8.8 -t ORG -t ASN
2021-06-30 18:03:06 analysis ip-inspector.cli[20141] INFO created: Whitelist Entry #1: entry_type=whitelist infrastructure_context_id=1 org=GOOGLE asn=15169 country=None insert_date=2021-06-30 22:03:06.243568 reference=8.8.8.8
```

#### List Removals

`ip-inspector whitelist remove 8.8.8.8`

```console
$ ip-inspector whitelist remove 8.8.8.8
2021-06-30 18:05:57 analysis ip-inspector.database[20453] INFO deleting 1 Whitelist entries
2021-06-30 18:05:57 analysis ip-inspector.database[20453] INFO Deleting Whitelist Entry #1: entry_type=whitelist infrastructure_context_id=1 org=GOOGLE asn=15169 country=None insert_date=2021-06-30 22:03:06.243568 reference=8.8.8.8 
2021-06-30 18:05:57 analysis ip-inspector.cli[20453] INFO successfully removed matching whitelist entries.
```

### Infrastructure Tracking Contexts

Infrastructure Tracking Contexts add another dimension to whitelists and blacklists that allow for more creative use cases.

#### Create New

Create a new Infrastructure Tracking Context named *user_authentications*.

`ip-inspector --create-tracking-context user_authentications`

```console
$ ip-inspector --create-tracking-context user_authentications
2021-06-30 18:08:00 analysis ip-inspector.cli[20692] INFO created new infrastructure context: Infrastructure Context: ID=2, Name=user_authentications, Insert Date=2021-06-30 22:08:00.217771
```

#### See Existing

`ip-inspector --print-tracking-contexts`

```console
$ ip-inspector --print-tracking-contexts
Infrastructure Context: ID=1, Name=default, Insert Date=2021-06-30 21:24:42.274827
Infrastructure Context: ID=2, Name=user_authentications, Insert Date=2021-06-30 22:08:00.217771
```

#### Delete One

Deletions are by ID, not name.

```console
$ ip-inspector --delete-tracking-context 2
2021-07-01 18:24:44 analysis ip-inspector.database[2153] WARNING deleting: Infrastructure Context: ID=3, Name=user_authentications, Insert Date2021-06-30 22:08:00.217771
2021-07-01 18:24:44 analysis ip-inspector.cli[2153] INFO deleted infrastructure context.
```

