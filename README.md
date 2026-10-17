# boxes

A procedural generator for HTB-style vulnerable machines. You ask for a number
of steps to the user flag and a number of further steps to the root flag, and it
generates a machine: a random-but-coherent chain of exploits drawn from a
library of "recipes".

It works in three layers:

1. **Plan** — symbolic facts + recipes, no VMs. Generates a machine and prints a
   walkthrough.
2. **Build/verify** — provisions a real target and runs each recipe's PoC.
   Containers are the fast path; QEMU is available for VM-only recipes.
3. **Check** — a plan is only emitted if every precondition was met earlier, and
   a recipe is only considered proven if its PoC exits 0.

Status: **P0 and P1 done.** P2 is partial — QEMU, pre-baked VM bases and
snapshots are working; multi-path emits independent paths (shared-prefix DAG is
next); VM attacker-context PoCs need the `boxes net` helper.

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
- **1 step to root:** `sudo` misconfiguration.
- **2 steps to root:** local enumeration finds a SUID binary → GTFOBins.

VM recipes (QEMU, TCG-verified):

- `sudo-misconfig-privesc` — target-context sudo escalation; has both container
  and VM PoCs.
- `vm-ssh-foothold` — attacker-context SSH foothold over a tap network
  (requires the `boxes net` sudoers helper).

Multi-path (`--multi-path N`) generates and verifies N independent full paths.

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

### Multi-path (experimental)

```bash
boxes gen --multi-path 2 --seed 42 --to-user 3 --to-root 2
boxes verify --machine --multi-path 2 --seed 42 --to-user 3 --to-root 2
```

`--multi-path N` (default 2) produces N distinct paths. Today each path is
verified on its own machine; shared-prefix DAG merging is next. It is only
valid with `gen` and `verify --machine`.

## Recipe tooling

`boxes new <id> --kind <kind>` scaffolds a `recipe.yaml` that already passes lint
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
difficulty: 0.3
yields: ["root"]         # omit unless this step reaches a flag
requires:
  - access_shell($u)
provides:
  - access_root()
params:
  binary:
    type: choice         # choice | password | token
    values: ["/usr/bin/find"]
walkthrough: |
  ... uses `{binary}` and `{u}` ...
```

`boxes lint` catches unknown predicates, wrong arity, unbound variables in
`provides`, a flag yielded by the wrong kind, a bad `poc.context`, a non-concrete
`open_port`, and flags reachable with no real work.

## Verification

### Backends

- **Docker** (`--backend docker`, default) — fast verification proxy: target and
  attacker containers on a per-machine `--internal` network.
- **QEMU** (`--backend qemu`) — the real product: a VM with the same
  provisioning, plus snapshots.
- **Fake** — in-memory, for unit tests.

The product is always a VM. `poc.container` is a fast verification proxy; a
container pass is accepted without a VM re-run, provided the container and VM
bases stay behaviourally aligned. `poc.vm` is for behaviour a container cannot
reproduce (kernel/boot/init). A recipe with both can be verified on either.

```bash
# one-time Docker images (target + attacker)
boxes image build --os ubuntu-22.04

# L2: one recipe in isolation
boxes verify --recipe sudo-misconfig-privesc

# L2: every verifiable container recipe
boxes verify --all

# L3: a full chain
boxes verify --machine --to-user 3 --to-root 2 --seed 0
```

The target image carries `vsftpd`, `openssh-server`, `openssh-client` and
`sshpass`; the attacker image (`boxes/attacker:latest`) carries `nmap`, `curl`,
`sshpass`, `python3`, `netcat`, `socat` and friends. It grows as recipes need
more tooling.

### Recipe verification contract

```yaml
provision: ./provision.sh    # shared; runs as root in the target
poc:
  context: attacker          # attacker | target
  container: ./poc.sh        # fast container verification (optional)
  vm: ./poc-vm.sh            # VM variant (optional)
actor: $u                    # target-context principal (default: attacker)
poc_timeout: 120
```

One recipe, no duplicates. `container` and `vm` are independent PoCs for the
same step; a recipe with only `container` is container-verified, one with only
`vm` is VM-verified. `verify --backend docker` skips recipes without a container
PoC; `--backend qemu` skips recipes without a VM PoC. `verify --machine`
requires every step to support the chosen backend.

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
the image ID (not just the tag), and the backend fidelity. A hit skips the
machine entirely. Only successes are stored, so failures always retry. The cache
lives in `.boxes-cache/` (gitignored).

```bash
boxes verify --all --jobs 4       # parallel, cold
boxes verify --all                # cache hits
boxes verify --all --no-cache     # force re-run
boxes verify --all --clear-cache  # wipe first
```

`--jobs` parallelizes independent recipes. Chain verification is sequential
because every step depends on the previous ones. Container timings on this host:
11 recipes cold with 4 jobs ≈ 30 s (the package probe installs via the proxy);
warm cache ≈ 0.3 s.

## VM backend (experimental)

Prerequisites: `qemu-system-x86`, `cloud-image-utils`, `libguestfs-tools`, and a
KVM-capable host for usable speed. TCG works, at roughly 1.5 minutes per boot.
Pre-bake the base once (cloud-init is run once; subsequent boots skip it):

```bash
boxes image build --backend qemu --os ubuntu-22.04
boxes verify --recipe sudo-misconfig-privesc --backend qemu
```

Measured on a TCG-only host: pre-bake ≈ 4m36s, cold verify ≈ 1m48s, warm cache
≈ 0.16s, `savevm` ≈ 2s, `loadvm` ≈ 7s.

Snapshots (`savevm`/`loadvm`) let a provisioned VM be restored. VM verification
takes a `pre-poc` snapshot after provisioning (and sealing), runs the PoCs, then
`loadvm pre-poc` restores the provisioned state. Multi-path VM verification
boots once: `savevm clean`, then for each path `loadvm clean` → provision →
`savevm pre-poc` → PoCs → `loadvm pre-poc`. Attacker-context paths currently
fall back to one machine per path because resetting the attacker container
between snapshots is not wired yet.

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
boxes verify --recipe vm-ssh-foothold --backend qemu --no-cache
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
boxes proxy status
boxes proxy down
boxes proxy clean     # also remove the cache volume
```

`boxes proxy up` builds `boxes/proxy` (apt-cacher-ng), starts `boxes-proxy` on
the `boxes-provision` Docker network, and attaches it to `br-provision` at
`10.67.0.2`. Provisioning receives:

- `BOX_PROXY_URL` and `http_proxy`/`https_proxy` pointing at
  `http://10.67.0.2:3142`;
- a provision NIC (`10.67.0.x`) on `br-provision`, configured by the backend;
- a `seal` step after provisioning that brings that NIC down.

The VM's management NIC uses QEMU `restrict=on`, so SSH hostfwd still works but
the guest has no route to the host or internet. During provisioning, apt goes
to the proxy; after the seal, only the host-only attack network remains.

The proxy cache is a persistent Docker volume (`boxes-proxy-cache`). It covers
apt today; pip/artifact proxying and pinned snapshot dates are the next step.

The sudoers rule must allow the helper subcommands, hence `boxes net *`.

## Roadmap

| Stage | Scope | Status |
|-------|-------|--------|
| **P0** — symbolic generation | Facts + unification, typed predicates, recipes, bounded-length planner, `open_port` prelude, causal connectivity, two-seed manifest, lint, scaffold, per-recipe harness | **Done** |
| **P1** — container fast path | Pluggable backend, target + attacker images, internal network, shared attacker container, provision/poc contract, assets, L2 + L3 verification, content-addressed cache, parallel jobs, real recipes | **Done** |
| **P2** — fidelity + branching | QEMU + prebaked base + snapshots; `poc.container`/`poc.vm` per recipe; pre-PoC snapshot/restore; one-VM multi-path (`clean` + `pre-poc` snapshots, target-context); provisioning proxy on `br-provision` with egress-only phase and seal; shared-prefix DAG and attacker reset across VM paths next | **Partial** |
| **P3** — coherence + scale | Difficulty budgets, themes, typed choices, more distros, a complete attacker toolkit | Planned |
| **P4** — registry | Recipe registry API + client, signed recipes, sandboxed execution, per-recipe CI | Planned |
