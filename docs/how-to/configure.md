## Configuring IP Inspector

If you're doing anything other than using `ip-inspector` on the command line, you may need to change the default behavior to fit your needs. For example, a team may want to share license keys and a common data directory for being in-sync with each other.

Configuration items can be overridden on a system and user level. Config items take the following precedence, where items found later override earlier ones:

1. System Level
2. User level
3. Special Environment Variables

> The `ip-inspector --customize` command will write a local copy of the current config, to a file named `ip_inspector.config.json` in the current working directory.
> You can use this copy of the current config to help you make the changes you desire. 
> I recommend removing anything that you are not explicitly overriding. You will then need to supply the changes at the system level or user level (see below).
> A convenience function exits to supply updates to the user level config: `ip-inspector --update-config path/to/updates.json`.

### System Level Overrides

The following file is checked for any system level overrides:
`/etc/ip_inspector/system.config.overrides.json` 

### User Level Overrides

User level overrides are saved at `~/.ip_inspector/etc/local.config.overrides.json`. This is the default location overrides are saved to by the `ip-inspector --update-config path/to/updates.json` command.

### Changing the default working directory

`ip-inspector` 

You can change the working directory three ways:

- Setting the `IP_INSPECTOR_WORK_DIR_PATH` environment variable before loading `ip-inspector`.
- Setting the default "work_dir" in a system wide config file.
- Setting the default "work_dir" in a user level config file.

---
*Navigation*

- [Home](../../README.md)
- [Guide](../how-to.md)