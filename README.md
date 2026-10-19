# boxes

A procedural generator for HTB-style vulnerable machines. You ask for a number
of steps to the user flag and a number of further steps to the root flag, and it
generates a machine: a random-but-coherent chain of exploits drawn from a
library of "recipes".

It works in three layers:

1. **Plan** — symbolic facts + recipes, no VMs. Generates a machine and prints a
   walkthrough.
2. **Build/verify** — provisions a real target and runs each recipe's PoC.
   Containers are the fast path; QEMU verifies the real VM product, including
   VM-only recipes.
3. **Check** — a plan is only emitted if every precondition was met earlier, and
   a recipe is only considered proven if its PoC exits 0.

Status: **P0–P3 done. P4 in progress.** Numeric recipe difficulty (1–10),
typed parameters/usernames, the manifest-driven attacker toolkit, the Ubuntu
22.04/24.04 + Debian 12 matrix, and Docker acceptance are done. The signed
static registry and client are implemented (bundles, Ed25519 trust, lockfile,
install/update/verify, untrusted-tier guard); the API server, hardened sandbox,
and per-recipe CI are next. Themes remain deferred (>50 recipes).

## Quick start

```bash
# container fast path
boxes image build --os ubuntu-22.04
boxes proxy up                      # needs the sudoers rule below
boxes verify --all --jobs 4

# plan only
boxes gen --to-user 3 --to-root 2 --seed 42

# real VM product (prepares the VM base + Docker attacker image)
boxes image build --backend qemu --os ubuntu-22.04
boxes verify --machine --backend qemu --to-user 2 --to-root 1 --seed 0
```

## Concepts

- **Fact** — a typed atom describing world state, e.g. `open_port(target, 22)`,
  `creds(deploy, hunter2)`, `access_shell(deploy)`. Predicate arities live in
  `facts.SIGNATURES`; this is the typed context.
- **Credentials** — `creds(user, password)` is the username+password pair.
  Dotted subtypes describe other shapes: `creds.uname(user)`, `creds.pass(password)`,
  and later `creds.auth_header`, `creds.cookies`, `creds.ntlmv1`, ...
  `service_access(service)` is a capability; `service_access(service, user, secret)`
  carries the credentials used. Recipes that find creds normally provide the pair
  *and* both partials, so a consumer can use whichever it needs. Credential reuse
  (trying username×password combinations) and an AD-validity marker are future
  work; no scoping/realm model is imposed.
- **Recipe** — an operator: `requires` (preconditions), `provides` (effects),
  randomizable `params`, and a `walkthrough` template. A recipe is a template;
  its params are grounded per machine.
- **Plan** — an ordered chain of recipe applications where every `requires` is
  satisfied by an earlier `provides`.
- **Manifest** — the concrete values (passwords, usernames, chosen binaries)
  produced from a seed. It guarantees a password leaked in one step is exactly
  the one consumed by a later step.
- **Prelude** — things that are free and not steps: `nmap` (which reveals
  `open_port` facts) and the OS/host facts.

### Recipe kinds

| kind             | meaning                                             | may yield |
|------------------|-----------------------------------------------------|-----------|
| `discovery`      | produces knowledge only (paths, versions, hashes)    | —         |
| `service-access` | gains access to a service (e.g. FTP login)           | —         |
| `creds`          | obtains a usable credential/artifact                 | —         |
| `foothold`       | obtains an interactive shell                         | user      |
| `privesc`        | escalates to root                                    | root      |

A step that yields the user flag must be a `foothold`; the root flag a `privesc`.
Credential reuse vs. default/common credentials is not a separate kind — it is a
difference in `requires`, which the planner handles.

### Two invariants

1. **Doability by construction** — a plan only exists if every precondition was
   met earlier.
2. **Causal connectivity** — every step must lie on a dependency path to a flag,
   using actual fact sharing (not mere unifiability). Steps may fan out and merge,
   but dead-end branches and redundant producers are rejected, so depth cannot be
   padded with filler.

## What it can build

Container recipes (all verified end-to-end):

- **3 steps to user (FTP):** default FTP creds → leak SSH creds from the share →
  SSH foothold.
- **3 steps to user (web):** directory brute force → admin panel leaks creds →
  SSH foothold.
- **2 steps to user:** exposed `.env` → SSH foothold.
- **1 step to user:** unauthenticated RCE → reverse shell (a legitimate
  one-step foothold, not a shortcut).
- **1 step to root:** `sudo` misconfiguration, or a SUID `find` binary.
- **2 steps to root:** local enumeration finds a SUID binary → GTFOBins.

VM recipes (QEMU-verified with KVM when available, TCG fallback):

- `web-env-leak-creds` and `backup-creds` — credential leaks, container-verified
  and portable to the VM.
- `ssh-creds-foothold` — SSH foothold with a provision that works on containers
  and VMs.
- `sudo-misconfig-privesc` and `suid-find-privesc` — two root paths, verified in
  containers and portable to the VM.
- `vm-kernel-probe` — `poc.vm` smoke test (PID 1 is systemd, kernel boot image).
- `package-probe` — provisioning-proxy smoke test.

Supported distros: **Ubuntu 22.04, Ubuntu 24.04, and Debian 12** (matrix in
[Distros](#distros)).

Multi-path (`--multi-path N`) generates N paths sharing the user phase. On one
VM the shared prefix is provisioned once, then each root branch runs with a
fresh attacker; Docker verifies each path in its own fast container.

## Usage

Examples below assume `boxes` is installed and on `PATH`. Without installing,
prefix each with `PYTHONPATH=src python3 -m`. For the privileged VM helper,
install system-wide or in a venv (see "VM attacker PoCs" below).

```bash
boxes lint
boxes recipes
boxes gen --to-user 3 --to-root 2 --seed 42
boxes gen --to-user 3 --to-root 2 --seed 42 --build-seed 2
boxes gen --to-user 2 --to-root 1 --json
```

### Seeds

Two independent seeds:

- `--seed` picks the **plan** — which recipes, in what order.
- `--build-seed` materialises the **values inside** those recipes — usernames,
  passwords, filenames, chosen binaries.

Both are random when omitted and both are printed, so a machine can be
reproduced exactly. Supplying the same `--seed` with a different `--build-seed`
gives the same attack path with a different flavour.

Values are derived per `(build_seed, step instance, parameter)`. Plan variables
are numbered by position (`ftp-config-leak-creds#1.ssh_user`), so multiple
credential sets in one plan never collide. Params can be `choice`, `password`,
or `token` (randomised identifiers/filenames).

### Difficulty

Recipes carry a whole-number level from **1 (trivial) to 10 (hard)**. A
machine's difficulty is the **hardest recipe**, not a sum or mean. The user
phase and root phase are reported separately as levels, and both are shown in
the walkthrough/JSON.

The CLI filters are still bands with provisional boundaries:

| band | levels |
|---|---|
| easy | 1–3 |
| medium | 4–6 |
| hard | 7–10 |

If these boundaries prove too coarse once the catalogue is larger, the filters
can switch to numeric ranges without changing recipes.

```bash
boxes gen --difficulty medium --to-user 2 --to-root 1 --seed 42
boxes gen --user-difficulty easy --root-difficulty hard --to-user 2 --to-root 2 --seed 42
boxes verify --machine --difficulty hard --to-user 1 --to-root 1 --seed 42
```

- `--difficulty` constrains the machine (max of user and root).
- `--user-difficulty` constrains the user phase.
- `--root-difficulty` constrains the root phase.
- Filters are exact band matches and only apply to `gen` / `verify --machine`.

Length and **shape** (steps, exposed services, discoveries, attacker↔target
context switches) are reported separately, so a long easy machine does not
become hard just because it is tedious. Some depth/band combinations are
infeasible with the current catalogue; the CLI reports the requested bands
instead of silently dropping them.

### Multi-path

```bash
boxes gen --multi-path 2 --seed 42 --to-user 3 --to-root 2
boxes verify --machine --multi-path 2 --seed 42 --to-user 3 --to-root 2
```

`--multi-path N` (default 2) produces N distinct paths that share their user
phase. On QEMU the shared prefix is provisioned once (`savevm shared`), then
each root branch is provisioned and the attacker is reset. On Docker each path
is verified on its own fast container. It is only valid with `gen` and
`verify --machine`.

## Recipe tooling

`boxes new <id> --kind <kind> --difficulty easy|medium|hard` scaffolds a `recipe.yaml` (the band maps to level 2/5/8) that already passes lint
and the harness. `boxes test-recipe <id>` tests a recipe in isolation, with no
machine:

- grounds its params with fixture values;
- builds a minimal state satisfying its `requires`;
- checks its `provides` come out fully grounded;
- renders the walkthrough and checks for unresolved `{placeholders}`;
- negative-tests that removing a non-prelude requirement makes it inapplicable.

`--fixture` prints the grounded fixture. That fixture is the bridge between the
symbolic layer and real verification, and is what a registry CI would run.

### Adding a recipe

```yaml
id: my-recipe
version: 1.0.0
kind: privesc            # discovery | service-access | creds | foothold | privesc
os: ["ubuntu-*"]
difficulty: 5            # whole number 1–10
yields: ["root"]         # omit unless this step reaches a flag
requires:
  - access_shell($u)
provides:
  - access_root()
params:
  binary:
    type: choice         # choice | int | bool | username | password | token
    values: ["/usr/bin/find"]
walkthrough: |
  ... uses `{binary}` and `{u}` ...
```

### Parameter types

`params` are typed generators/validators, not just string choices:

- `choice` — fixed values, optionally weighted; values may be strings, ints, or bools.
- `int` — `min`, `max`, `step`.
- `bool` — random true/false.
- `username` — a human-looking account from small first/last/role wordlists.
- `password` / `token` — random strings with a configurable length.

```yaml
params:
  user:
    type: username
    styles: ["first_last", "flast"]   # default: first/last/flast/firstl/first_last
  port:
    type: int
    min: 8000
    max: 8090
    step: 10
  tls:
    type: bool
  binary:
    type: choice
    values: ["/usr/bin/find", "/usr/bin/python3"]
    weights: [3, 1]
```

Values are deterministic from the build seed. The manifest keeps their types;
provisioning/PoC env vars stringify them (`true` / `false` for bools, decimal
strings for ints). `username` is one generator type, not the whole typed system:
it draws from the wordlists in `src/boxes/names.py`, supports `first`, `last`,
`flast`, `firstl`, `first_last`, `role`, and `svc_role` styles, avoids system
accounts, and keeps generated names unique within a machine.

`boxes lint` catches unknown predicates, wrong arity, unbound variables in
`provides`, a flag yielded by the wrong kind, a bad `poc.context`, a non-concrete
`open_port`, malformed param specs, and flags reachable with no real work.

## Verification

### Backends

- **Docker** (`--backend docker`, default) — fast verification proxy: target and
  attacker containers on a per-machine `--internal` network.
- **QEMU** (`--backend qemu`) — the real product: a VM with the same
  provisioning, plus snapshots. KVM is used automatically when usable; TCG is
  the fallback (see "VM backend").
- **Fake** — in-memory, for unit tests.

The product is always a VM. `poc.container` is a fast verification proxy; a
container pass is accepted without a VM re-run, provided the container and VM
bases stay behaviourally aligned. `poc.vm` is for behaviour a container cannot
reproduce (kernel/boot/init), such as the `vm-kernel-probe` smoke recipe. A
recipe declares exactly one of the two; a container PoC is also allowed on the
VM, while a VM PoC is never run on a container.

```bash
# one-time Docker images (target + attacker)
boxes image build --os ubuntu-22.04

# start the provisioning proxy (needed for package-installing recipes)
boxes proxy up

# L2: one recipe in isolation
boxes verify --recipe sudo-misconfig-privesc

# L2: every verifiable container recipe
boxes verify --all

# L3: a full chain
boxes verify --machine --to-user 3 --to-root 2 --seed 0
```

The target base carries `vsftpd`, `openssh-server`, `openssh-client`, and
`sshpass` per distro. The attacker image (`boxes/attacker:latest`) is generated
from the toolkit manifest; see [Attacker toolkit](#attacker-toolkit).

### Recipe verification contract

```yaml
provision: ./provision.sh    # shared; runs as root in the target
poc:
  context: attacker          # attacker | target
  container: ./poc.sh        # exactly one of container/vm
actor: $u                    # target-context principal (default: attacker)
tools: [curl, sshpass]       # attacker commands (optional)
poc_timeout: 120
```

Exactly one of `container` or `vm` is required. A `container` PoC is the fast
proxy and is also allowed on the VM; a `vm` PoC is VM-only. Docker skips vm-only
recipes; QEMU accepts both. `verify --machine` requires every step to support
the chosen backend.

- `context: attacker` runs in the shared attacker container with `BOX_HOST` set
  to the target address (`target` on Docker, the tap IP on a VM). It cannot cheat
  by running inside the victim.
- `context: target` runs in the target as `actor` with
  `BOX_HOST=127.0.0.1`, which is right for local privesc steps.

Both scripts receive the grounded context as environment variables (`BOX_U`,
`BOX_BINARY`, `BOX_HOST`, `BOX_RECIPE`, `BOX_OS`, `BOX_ASSETS`, ...). The actor
is resolved from that context, so a target-context PoC runs as the principal the
step claims to act as — e.g. a root step runs as the user the foothold produced.
That is how a chain proves composability, not just isolated steps.

`boxes verify --machine` requires every step to have provision+poc; otherwise it
reports which are symbolic-only instead of silently skipping them.

### Distros

The default is Ubuntu 22.04; `--os` selects the target image/base:

```bash
boxes image build --os debian-12
boxes verify --all --os debian-12 --jobs 4

boxes image build --backend qemu --os debian-12
boxes verify --machine --backend qemu --os debian-12 \
    --to-user 2 --to-root 1 --seed 0
```

| OS | Docker | QEMU | VM store | Notes |
|---|---|---|---|---|
| `ubuntu-22.04` | 13/13 | probe + chain | `.boxes-vm/` | default; fastest TCG VM |
| `ubuntu-24.04` | 13/13 | probe + chain | `.boxes-vm/ubuntu-24.04/` | TCG prebake ~24 min, chain ~9 min; use KVM or `BOXES_VM_BOOT_TIMEOUT=1800` |
| `debian-12` | 13/13 | probe + chain | `.boxes-vm/debian-12/` | TCG chain ~2 min |

Container bases exist for Ubuntu 22.04, Ubuntu 24.04, and Debian 12. QEMU uses
a matching cloud image and the per-OS store shown above. The cloud image is
SHA-verified against the distro's `SHA256SUMS`/`SHA512SUMS` and the download is
resumable.

Ubuntu 24.04 cloud-init is noticeably heavier under TCG (prebake ~24 min,
probe ~8m44s, chain ~9m22s). The prebake/runtime boot timeout defaults to 900s
for prep and 600s for machines; for noble TCG use
`BOXES_VM_BOOT_TIMEOUT=1800`.

### Attacker toolkit

The attacker image is generated from `images/attacker/tools.yaml` into
`tools.txt`/`pip.txt`. It includes web tooling (`ffuf`, `gobuster`, `dirb`,
`nikto`, `sqlmap`), credentials (`hydra`, `john`, `hashcat`), SMB/LDAP/impacket,
and binary-analysis tools (`gdb`, `ltrace`, `strace`, `gcc`).

```bash
boxes image build --os ubuntu-22.04     # also builds the attacker image
boxes image tools                      # list apt/pip/commands
boxes image tools --check              # run every command in the image
```

Recipes declare `tools: [curl, sshpass]`; `boxes lint` rejects tools that are
not in the manifest.

### CI / acceptance

```bash
scripts/acceptance.sh             # unit, lint, 3-OS Docker matrix, Docker tests
scripts/acceptance.sh --with-vm   # also all 3 QEMU profiles, probes, and 2 chains
```

The Docker integration test suite is parametrized over the three distros.
`--with-vm` preps all three QEMU profiles, runs the VM-only probes, and runs
Debian and Ubuntu 24.04 chains (slow on TCG; `BOXES_VM_BOOT_TIMEOUT=1800` is
set by the script).

Scripts are arbitrary code. First-party recipes run as root inside a limited,
network-isolated container. A public registry must sandbox harder.

### Recipe assets

Put files in `recipes/<id>/files/` (or set `assets: ./dir`); they are copied to
`/opt/boxes/<id>/` in the target before provisioning, and `BOX_ASSETS` points
there. Use it for compiled PoCs, configs, templates, or payloads that are not
practical to inline in a shell script.

### Verification cache and parallelism

`verify` keys each result on the content of everything that can change it: the
recipe directory (yaml, scripts, assets), the grounded fixture/manifest values,
the image ID (including the attacker image for VM PoCs), the apt snapshot
date if one is pinned, and the backend fidelity. A hit skips the machine
entirely. Only successes are stored, so failures always retry. The cache
lives in `.boxes-cache/` (gitignored).

```bash
boxes verify --all --jobs 4       # parallel, cold
boxes verify --all                # cache hits
boxes verify --all --no-cache     # force re-run
boxes verify --all --clear-cache  # wipe first
```

`--jobs` parallelizes independent recipes. Chain verification is sequential
because every step depends on the previous ones. Container timings on this host:
13 recipes per OS cold with 4 jobs ≈ 15–30 s (the package probe installs via
the proxy); warm cache ≈ 0.5 s.

## VM backend

Prerequisites: `qemu-system-x86`, `qemu-utils`, `cloud-image-utils`,
`openssh-client`, `curl`, and Docker (attacker-context VM PoCs use the Docker
attacker container).

KVM is selected automatically when `/dev/kvm` is usable and the QEMU binary
reports the `kvm` accelerator; otherwise TCG is used. The same selection applies
to the prebake and to runtime verification. Override it with
`--accel auto|kvm|tcg` on `image build`/`verify`, or with
`BOXES_QEMU_ACCEL`. An explicit `--accel kvm` fails clearly when KVM is not
usable instead of silently falling back. On this TCG-only host a boot takes
roughly 1.5–2.5 minutes. Pre-bake the base once (cloud-init is run once;
subsequent boots skip it). This also builds the Docker attacker image:

```bash
# auto: KVM if usable, otherwise TCG
boxes image build --backend qemu --os ubuntu-22.04
boxes verify --recipe sudo-misconfig-privesc --backend qemu

# manual overrides (`--accel kvm` requires usable KVM)
boxes image build --backend qemu --os ubuntu-22.04 --accel kvm
BOXES_QEMU_ACCEL=tcg boxes verify --machine --backend qemu --seed 0
```

The cloud image download is resumable (`<codename>-base.img.part`), validated
as a qcow2, and checked against the distro's `SHA256SUMS`/`SHA512SUMS`. The VM
store defaults to `.boxes-vm` for Ubuntu 22.04 and `.boxes-vm/<os>` for the
other profiles; override the root with `BOXES_VM_STORE` (and the base path with
`BOXES_VM_BASE`).

Measured on a TCG-only host: pre-bake ranges from ~2.5 min (Debian 12, warm
network) to ~24 min for Ubuntu 24.04's first cloud-init boot; cold verification
ranges from ~1–3 min (Ubuntu 22.04/Debian 12) to ~9 min (Ubuntu 24.04); warm
cache ≈ 0.5–1 s, `savevm` ≈ 2 s, `loadvm` ≈ 7 s. KVM hosts use KVM for both prep
and verification. Raise `BOXES_VM_BOOT_TIMEOUT` for slow TCG boots.

Snapshots (`savevm`/`loadvm`) let a provisioned VM be restored. VM verification
takes a `pre-poc` snapshot after provisioning (and sealing), runs the PoCs, then
`loadvm pre-poc` restores the provisioned state. Multi-path VM verification
boots once: configure apt, `savevm clean`, provision the shared prefix,
`savevm shared`, then for each branch `loadvm shared` → branch provision →
`savevm pre-poc` → PoCs → `loadvm pre-poc`. For attacker-context paths the
attacker container is recreated and a fresh veth is attached to the existing
attack bridge before the branch is provisioned.

### VM attacker PoCs (tap + bridge + veth)

A VM and the Docker attacker container must share an L2 segment. `boxes net
up/down` is the only part that needs root. Install `boxes` so root can import
it; pick either option:

**System-wide (simplest):**

```bash
sudo pip install --break-system-packages -e /path/to/boxes
command -v boxes                     # usually /usr/local/bin/boxes
```

**Venv (isolated, no system Python changes):**

```bash
python3 -m venv /opt/boxes-venv
/opt/boxes-venv/bin/pip install -e /path/to/boxes
```

`sudo` resets `HOME` to `/root`, so a user-site install (`~/.local/...`) is
invisible to root; that is why the helper needs a system-wide install or the
venv binary.

Allow the helper in sudoers, using the path from `command -v boxes` (or the venv
binary):

```
user ALL=(root) NOPASSWD: /usr/local/bin/boxes net *
```

For the venv, put `/opt/boxes-venv/bin/boxes` in the rule and run with
`BOXES_BIN=/opt/boxes-venv/bin/boxes`.

Check the privilege path on its own:

```bash
sudo -n /usr/local/bin/boxes net down testrule   # {"machine": "testrule", "removed": true}
```

Then:

```bash
boxes verify --recipe ssh-creds-foothold --backend qemu --no-cache
```

`boxes net up <id> --attacker-pid <pid> --user <user>` creates `br-<id>`,
`tap-<id>`, `veth-<id>`, moves the container end into the attacker netns
(`eth0`, `10.66.1.3/24`), and leaves the VM tap for QEMU (`10.66.1.2/24`).
`boxes net down <id>` removes them. It also inserts a scoped
`iptables -I FORWARD -i br-<id> -o br-<id> -j ACCEPT` (Docker enables
`br_netfilter`, so bridged IP traffic would otherwise hit the FORWARD DROP
policy); `down` removes that rule too.

**This runs per machine start, not once.** Only the bridge could persist; the tap
is tied to the VM boot and the veth to the attacker container's netns.

If the sudoers rule is missing, sudo is non-interactive, or `boxes` is not on
`PATH`, verification prints a warning and marks the recipe unverifiable instead
of crashing:

```
warning: cannot set up VM attacker networking, so the attacker-context PoC
cannot run and this recipe cannot be verified...
```

Set `BOXES_BIN=/absolute/path/to/boxes` if the console script is not on `PATH`.
The attack bridge has no uplink or host IP; the VM's management NIC (user-mode +
SSH hostfwd) is separate. If QEMU cannot open the pre-created tap unprivileged,
give a QEMU wrapper `cap_net_admin` or pass the tap fd from the helper.

### Provisioning proxy (`br-provision`)

Targets get **no direct internet**. During provisioning a VM gets an extra NIC
on the shared `br-provision` bridge, where the proxy container lives; that NIC
is brought down before PoCs. The proxy is the only egress.

```bash
boxes proxy up        # build/start boxes-proxy, create br-provision
boxes proxy status    # includes a running/healthy check for :3128, :3142, :8000
boxes proxy down
boxes proxy clean     # also remove the Docker network, cache volume, and artifacts
```

`boxes proxy up` builds `boxes/proxy` (apt-cacher-ng + squid + a static
artifact server), starts `boxes-proxy` on the `boxes-provision` Docker network,
and attaches it to `br-provision` at `10.67.0.2`. Provisioning receives:

- `BOX_PROXY_URL` plus `http_proxy`/`https_proxy` at
  `http://10.67.0.2:3128` (or `http://boxes-proxy:3128` for containers);
- `BOX_APT_PROXY` at `http://10.67.0.2:3142` (or
  `http://boxes-proxy:3142`), written into `/etc/apt/apt.conf.d/01boxes`;
- `BOX_ARTIFACTS_URL` at `http://10.67.0.2:8000` (or
  `http://boxes-proxy:8000`);
- a provision NIC (`10.67.0.x`) on `br-provision`, configured by the backend;
- a `seal` step after provisioning that brings that NIC down.

The VM's management NIC uses QEMU `restrict=on`, so SSH hostfwd still works but
the guest has no route to the host or internet. During provisioning, apt and pip
go to the proxy; after the seal, only the host-only attack network remains.

apt uses the **durable** apt-cacher-ng cache (volume `boxes-proxy-cache`); pip
and other HTTP goes through squid (in-memory cache), with HTTPS tunneled via
CONNECT. An origin allowlist limits squid to Ubuntu/Debian/PyPI/GitHub. The
artifact store is `.boxes-cache/artifacts`, served at `:8000`; recipes fetch
pinned files from `$BOX_ARTIFACTS_URL`.

Pin a full apt snapshot with `--apt-snapshot`:

```bash
boxes verify --recipe package-probe --apt-snapshot 20240101T000000Z
```

The runner rewrites the distro sources to HTTPS on `snapshot.ubuntu.com` /
`snapshot.debian.org`, refreshes the indexes, and keeps the pinned state for the
rest of the machine (the cache key includes the date). Snapshot hosts bypass
apt-cacher-ng and go through squid: apt-cacher-ng mishandles the snapshot
service's HTTP→HTTPS by-hash redirects. After a host or Docker restart, run
`boxes proxy up` again; slow TCG installs can be given more time with
`BOXES_PROVISION_TIMEOUT` (seconds, default 1200).

The sudoers rule must allow the helper subcommands, hence `boxes net *`.

## Registry (P4, in progress)

The first P4 slice is a **signed static registry** and client. A registry is a
directory (or HTTP prefix) with a signed `index.json` and content-addressed
bundles:

```text
registry/
  index.json
  bundles/<bundle-sha256>.tar.gz
```

A bundle is a deterministic `tar.gz` containing `bundle.json` and the recipe
files. The index is signed by the **registry operator** key; every bundle is
signed by its **publisher** key and content-addressed by its manifest hash.
Signatures establish provenance, not safety.

```bash
# keys: private (<out>.key, 0600) and public (<out>.pub)
boxes registry keygen --out ~/.config/boxes/dev

# publish a recipe directory to a static registry
boxes registry publish recipes/my-recipe \
    --registry-dir /srv/boxes-registry \
    --publisher me --key ~/.config/boxes/dev.key

# trust a registry by pinning its operator public key
boxes registry add local /srv/boxes-registry --key ~/.config/boxes/dev.pub

boxes registry search web
boxes registry install my-recipe
boxes registry update
boxes registry verify
boxes registry uninstall my-recipe
```

- Config: `~/.config/boxes/registries.json` (override with `BOXES_CONFIG_FILE`
  or `BOXES_CONFIG_DIR`).
- Installed recipes: `.boxes-registry/recipes/<id>/` (gitignored); the project
  `boxes.lock` pins registry URL/operator fingerprint, bundle hash, publisher
  key/signature, file hashes, and the verified index sequence.
- Rollback protection: a signed index whose sequence is lower than the
  client's remembered sequence is refused. The lock is the local pin; the
  signed index is re-fetched for `verify`/`update` unless `--offline` is used.
- Tampering with the index, bundle, file, publisher key, or lock manifest is
  rejected.

### Untrusted tier

Registry-installed recipes are **untrusted**. Until the hardened sandbox
milestone lands:

- QEMU verification of an installed registry recipe is refused;
- Docker verification requires an explicit opt-in:

```bash
boxes verify --recipe my-recipe --allow-untrusted
```

The opt-in warns that the current container runner is not yet the locked
sandbox. First-party recipes in `recipes/` remain the trusted local tier. The
next P4 milestones are the reference API server, the locked Docker sandbox +
attestations, and per-recipe CI.

## Roadmap

| Stage | Scope | Status |
|-------|-------|--------|
| **P0** — symbolic generation | Facts + unification, typed predicates, recipes, bounded-length planner, `open_port` prelude, causal connectivity, two-seed manifest, lint, scaffold, per-recipe harness | **Done** |
| **P1** — container fast path | Pluggable backend, target + attacker images, internal network, shared attacker container, provision/poc contract, assets, L2 + L3 verification, content-addressed cache, parallel jobs, real recipes | **Done** |
| **P2** — fidelity + branching | QEMU (KVM auto/TCG fallback) + prebaked base + snapshots; one PoC per recipe (`poc.container` XOR `poc.vm`); pre-PoC snapshot/restore; shared-prefix DAG with one-VM verification and attacker reset; hybrid provisioning proxy (durable apt cache + squid + artifact store) with egress-only phase and seal; apt snapshot pinning; VM base checksum/resume/store overrides; proxy health/cleanup | **Done** |
| **P3** — coherence + scale | Numeric difficulty 1–10 (machine = hardest recipe; separate user/root; provisional easy/medium/hard CLI bands; length/shape separate); typed params and human-looking usernames; weighted choices; manifest-driven attacker toolkit with lint/check; Ubuntu 22.04/24.04 + Debian 12 Docker (13/13 each); QEMU profiles, per-OS stores, and verified VM chains on all three; Docker integration matrix and acceptance script. Themes deferred until the catalogue is large enough (>50 recipes); planner-scale tuning as it grows. | **Done** |
| **P4** — registry | In progress: signed static registry and client, deterministic content-addressed bundles, Ed25519 operator/publisher signatures, rollback protection, lockfile, install/update/verify, untrusted-tier guard. Next: reference API server, hardened sandbox + attestations, per-recipe CI. | **In progress** |
