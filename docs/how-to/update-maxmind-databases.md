## MaxMind GeoLite2 Database Updates

Depending on your use cases and/or preferences, you can either use `ip-inspector` to keep your databases updated (last I recall, the databases come out every Tuesday) or you can use the MaxMind `geoipupdate` tool to keep your system databases updated. See below for details on both methods.

### Using geoipupdate

MaxMind provides the [geoipupdate](https://dev.maxmind.com/geoip/geoipupdate/) tool for keeping your system databases updated. Follow their instructions, supply your [license key](https://www.maxmind.com/en/geolite2/signup), and set up your cronjob.

Example config @  `/etc/GeoIP.conf` :

```
# For more information about this config file, visit the docs at
# https://dev.maxmind.com/geoip/geoipupdate/.

# `AccountID` is from your MaxMind account.
AccountID 0123456789

# `LicenseKey` is from your MaxMind account
LicenseKey v8asdfjkhfakes

# `EditionIDs` is from your MaxMind account.
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country

Proxy proxy.address:proxy_port
ProxyUserPassword user:pass
```

Cron job:

```
49 5 * * 1,4 /usr/local/bin/geoipupdate
```

### Using IP Inspector

 If you want to use ip-inspector to download and maintain your GeoLite2 databases, you will need to provide the license key. The easiest method is to supply the key on the command line.

Supplying the license key via the command line will save the key for future use by the current user. Example:

```console
$ ip-inspector -lk 'your_license_key'
```

Next, with the license key, you can use the update command to download the most recent databases files.

```
$ ip-inspector -u
```

Now, you could call the above with a cron job. Don't forget to set your environment variables, as needed.

#### The Update Code:

Additionally, here is an example script showing how to update the databases:

```python
import logging
from ip_inspector import maxmind

# TODO: load your license key and get your proxy settings.
if maxmind.update_databases(license_key=license_key, proxies=proxies):
    logging.info("successfully updated the MaxMind GeoLite2 databases.")
```


---
*Navigation*

- [Home](../../README.md)
- [Guide](../how-to.md)
