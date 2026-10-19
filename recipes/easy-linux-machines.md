# Easy Linux machine recipe packs

These packs are inspired by the first ten Linux machines in the easy-machine
writeup catalogue. Each pack keeps the attack steps as separate recipes so the
planner can reuse or substitute a step, and login steps require
`creds.uname($u)` plus `creds.pass($p)` separately.

The recipes use dedicated ports (for example `8081`, `8445`, `8053`) so that all
steps in a pack can be provisioned into one target without replacing each
other's services.

| Machine | User path | Root path |
|---|---|---|
| **Lame** | `samba-version-discovery` → `samba-usermap-foothold` | `samba-usermap-root` |
| **Beep** | `web-gobuster-discovery` → `elastix-lfi-creds` → `ssh-creds-foothold` | `sudo-enumeration` → `sudo-all-privesc` |
| **Shocker** | `web-gobuster-discovery` → `shellshock-cgi-foothold` | `sudo-misconfig-privesc` (Perl) |
| **Nibbles** | `web-gobuster-discovery` → `web-admin-panel-creds` → `web-upload-foothold` | `sudo-monitor-discovery` → `sudo-script-privesc` |
| **Bashed** | `web-gobuster-discovery` → `phpbash-foothold` | `cron-discovery` → `cron-writable-privesc` |
| **Mirai** | `web-gobuster-discovery` → `pihole-default-creds` → `ssh-creds-foothold` | `sudo-enumeration` → `sudo-all-privesc` |
| **Blocky** | `web-gobuster-discovery` → `web-jar-creds` → `ssh-creds-foothold` | `sudo-enumeration` → `sudo-all-privesc` |
| **Cronos** | `dns-zone-transfer-discovery` → `web-gobuster-discovery` → `sqli-admin-creds` → `web-command-injection-foothold` | `cron-discovery` → `cron-writable-privesc` |
| **Bank** | `dns-zone-transfer-discovery` → `bank-upload-bypass-foothold` | `suid-emergency-discovery` → `suid-emergency-privesc` |
| **Valentine** | `heartbleed-discovery` → `heartbleed-key-foothold` | `tmux-session-discovery` → `tmux-hijack-privesc` |

For example, the Nibbles pack is generated with two user-phase steps before the
foothold, so it uses `--to-user 3 --to-root 2`:

```bash
boxes verify --machine --to-user 3 --to-root 2 --seed 0
```

When verifying only a pack, point `--recipes` at a directory containing just
those recipe directories. The normal project registry can still use the packs
together with the generic recipes.

## Second batch: the next ten Linux machines

The next ten Linux entries in the catalogue (skipping Luke, whose writeup is
FreeBSD, and substituting OpenAdmin) are below.

| Machine | User path | Root path | Verify shape |
|---|---|---|---|
| **Irked** | `irc-service-discovery` → `irc-backdoor-foothold` → `steg-password-creds` → `ssh-creds-foothold` | `viewuser-suid-discovery` → `viewuser-privesc` | `--to-user 4 --to-root 2` |
| **Curling** | `web-gobuster-discovery` → `joomla-secret-creds` → `web-auth-shell-access` → `password-backup-creds` → `ssh-creds-foothold` | `cron-discovery` → `cron-writable-privesc` | `--to-user 5 --to-root 2` |
| **FriendZone** | `web-gobuster-discovery` → `smb-guest-creds` → `web-auth-shell-access` → `service-config-creds` → `ssh-creds-foothold` | `python-library-hijack-privesc` | `--to-user 5 --to-root 1` |
| **SwagShop** | `web-gobuster-discovery` → `magento-admin-creds` → `web-upload-foothold` | `sudo-wrapper-privesc` (`vi`) | `--to-user 3 --to-root 1` |
| **Networked** | `web-gobuster-discovery` → `web-shell-access` → `cron-pivot-foothold` | `ifcfg-privesc` | `--to-user 3 --to-root 1` |
| **Haystack** | `elasticsearch-creds` → `ssh-creds-foothold` | `kibana-lfi-pivot` → `logstash-privesc` | `--to-user 2 --to-root 2` |
| **Writeup** | `web-gobuster-discovery` → `cmsms-sqli-creds` → `ssh-creds-foothold` | `run-parts-privesc` | `--to-user 3 --to-root 1` |
| **Postman** | `redis-key-foothold` → `cracked-key-creds` → `ssh-creds-foothold` | `webmin-privesc` | `--to-user 3 --to-root 1` |
| **Traverxec** | `web-gobuster-discovery` → `web-shell-access` → `htpasswd-creds` → `ssh-creds-foothold` | `sudo-wrapper-privesc` (`journalctl`) | `--to-user 4 --to-root 1` |
| **OpenAdmin** | `web-gobuster-discovery` → `opennetadmin-rce-foothold` → `opennetadmin-db-creds` → `internal-site-pivot` | `sudo-wrapper-privesc` (`nano`) | `--to-user 4 --to-root 1` |

The two batches now cover twenty Linux machines from the easy catalogue. Every
login/access step uses separate `creds.uname` and `creds.pass` facts, and every
user-yielding step provides both `access_shell` and `user_shell`; root steps
consume `user_shell` so they run as the actual user principal rather than an
earlier service account.

## Third batch: the next ten Linux machines

| Machine | User path | Root path | Verify shape |
|---|---|---|---|
| **Traceback** | `web-gobuster-discovery` → `phpbash-foothold` | `sudo-wrapper-privesc` (`luvit`) | `--to-user 2 --to-root 1` |
| **Admirer** | `web-gobuster-discovery` → `web-admin-panel-creds` → `ssh-creds-foothold` | `python-path-privesc` | `--to-user 3 --to-root 1` |
| **Blunder** | `web-gobuster-discovery` → `web-admin-panel-creds` → `web-upload-foothold` | `blunder-sudo-cve-privesc` | `--to-user 3 --to-root 1` |
| **Tabby** | `web-gobuster-discovery` → `elastix-lfi-creds` → `web-upload-foothold` | `lxd-privesc` | `--to-user 3 --to-root 1` |
| **Doctor** | `doctor-ssti-foothold` → `adm-log-creds` → `ssh-creds-foothold` | `splunk-privesc` | `--to-user 3 --to-root 1` |
| **Academy** | `laravel-rce-foothold` → `service-config-creds` → `ssh-creds-foothold` | `sudo-wrapper-privesc` (`composer`) | `--to-user 3 --to-root 1` |
| **Laboratory** | `gitlab-ssrf-creds` → `ssh-creds-foothold` | `docker-security-privesc` | `--to-user 2 --to-root 1` |
| **Help** | `web-gobuster-discovery` → `phpbash-foothold` | `kernel-privesc` | `--to-user 2 --to-root 1` |
| **LaCasaDePapel** | `vsftpd-backdoor-foothold` → `lacasa-cert-creds` → `ssh-creds-foothold` | `cron-ini-privesc` | `--to-user 3 --to-root 1` |
| **ScriptKiddie** | `msfvenom-template-foothold` | `sudo-wrapper-privesc` (`msfconsole`) | `--to-user 1 --to-root 1` |

Traceback, Academy, and ScriptKiddie reuse the sudo-wrapper root primitive with
`luvit`, `composer`, and `msfconsole` respectively. The three batches now cover
thirty Linux machines from the easy catalogue.
