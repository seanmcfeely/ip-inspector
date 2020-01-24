# IP Inspector

IP Inspector is a command line tool and library for proving intel on IP addresses for the purpose of enabling Intel Detection and Response.

It's built to be modular so it can add value around any API that delivers IP address or computer network information. However, currently it only uses the free [GeoLite2 databases](https://dev.maxmind.com/geoip/geoip2/geolite2/) provided by [MaxMind](https://www.maxmind.com/en/home) and the tool/library can be used just interface with the MaxMind API in a convenient way. That said, I wrote this for the purpose of adding value to our intel, detect, and response program. That value is obtained by tracking and responding to IP addresses that show up in our detection apparatuses differently based on their metadata. With respect to ip-inspector that's achieved via simple blacklists and/or whitelists you can manually or programmatically maintain for the different IP address metadata fields valuable to your situation, such as the ASN, the Organization name, the country, etc.


## Install and Setup

`python3 -m pip install ip-inspector`


### MaxMind GeoLite2
The command line tool and MaxMind Client will first look for local MaxMind GeoLite2 database files (`$ ip-inspector -u`) and then look for system files at the following default locations (debian):


    /usr/share/GeoIP/GeoLite2-ASN.mmdb
    /usr/share/GeoIP/GeoLite2-City.mmdb
    /usr/share/GeoIP/GeoLite2-Country.mmdb

If you want to use ip-inspector to download and maintain your GeoLite2 databases. You can register for a free license key here: [https://www.maxmind.com/en/geolite2/signup](https://www.maxmind.com/en/geolite2/signup)

Then there are a variety of ways to supply that license key, depending on how you want to use ip-inspector.  

Suppling on the command line will save your license key for future use:
```
$ ip-inspector -lk 'your_license_key'
```
Next, you can use the update command to download the most recent databases files.
```
$ ip-inspector -u
```

You can accomplish the same with the library, like so:
```python
from ip_inspector import maxmind
from ip_inspector import Inspector

# If you just want the maxmind client:
mmc = maxmind.Client(license_key='your_license_key')

# The Inspector with blacklist/whitelist functionality
mmi = Inspector(maxmind.Client(license_key='your_license_key'))
```

If you want to download a local copy of the GeoLite2 databases:
```python
from ip_inspector import maxmind

# I'm pretending we have already loaded a config and PROXIES, for the sake of the example and to show
# that update_databases accepts **args to pass to requests.
proxies = PROXIES if 'use_proxy' in config and config.getboolean('use_proxy') else None
maxmind.update_databases(license_key='your_license_key', proxies=proxies):
```

## Incomplete

I've implemented the minimum of what I needed to solve immediate needs but built this for long term use. Some features I planned on have not yet been implemented. If anyone reads this, you're wicked cool.

