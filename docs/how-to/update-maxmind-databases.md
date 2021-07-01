## MaxMind GeoLite2 Database Updates

Depending on your use cases and/or preferences, you can either use `ip-inspector` to keep your databases updated (last I recall, the databases come out every Tuesday) or you can use the MaxMind `geoipupdate` tool to keep your system databases updated. See below for details on both methods.

### Using geoipupdate

MaxMind provides the [geoipupdate](https://dev.maxmind.com/geoip/geoipupdate/) tool for keeping your system databases updated. Follow their instructions, supply your [license key](https://www.maxmind.com/en/geolite2/signup), and set up your cronjob.

Cron job:

```
14 5 * * 6 geoipupdate
```

### Using IP Inspector

 If you want to use ip-inspector to download and maintain your GeoLite2 databases, you will need to provide the license key. There are a couple of ways to supply that license key, depending on how you want to use ip-inspector.

Supplying on the command line will save your license key for future use:

```console
$ ip-inspector -lk 'your_license_key'
```

Next, with the license key, you can use the update command to download the most recent databases files.

```
$ ip-inspector -u
```

Now, you can call the above with a cron job. Don't forget to set your environment variables, as needed. TODO: provide bash script to call the cron job with.

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
[Click here](../../readme.md) to go back to the main page.