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
