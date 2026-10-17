# boxes

A procedural generator for HTB-style vulnerable machines. You ask for a number
of steps to the user flag and a number of further steps to the root flag, and it
generates a machine: a random-but-coherent chain of exploits, each drawn from a
library of "recipes".

**P0 is plan-only.** It reasons about machines symbolically and prints a
walkthrough. P1 adds a container fast path that provisions recipes and runs
their PoCs to prove them (see "P1 fast path" below). Full-fidelity VMs are P2.

## Concepts

- **Fact** — a typed atom describing world state, e.g. `open_port(target, 22)`,
  `creds(deploy, hunter2)`, `access_shell(deploy)`. Predicate arities are
  declared in `facts.SIGNATURES`; this is the *typed context*.
- **Credentials** — `creds(user, password)` is the username+password pair.
  Dotted subtypes describe other shapes: `creds.uname(user)`,
  `creds.pass(password)`, and later `creds.auth_header`, `creds.cookies`,
  `creds.ntlmv1`, ... `service_access(service)` is a capability;
  `service_access(service, user, secret)` carries the credentials used. Recipes
  that find creds normally provide the pair *and* both partials, so a consumer
  can use whichever it needs (at least one provided fact must be consumed for
  the step to count as part of the chain).
- **Recipe** — an operator: `requires` (preconditions), `provides` (effects),
  randomizable `params`, and a `walkthrough` template. A recipe is a *template*;
  its params are grounded per-machine.
- **Plan** — an ordered chain of recipe applications where every `requires` is
  satisfied by an earlier `provides`.
- **Manifest** — the concrete values (passwords, usernames, chosen binaries)
  produced from a seed. The manifest is what guarantees a password leaked in one
  step is exactly the one consumed by a later step.
- **Prelude** — things that are free and not steps: `nmap` (which reveals
  `open_port` facts) and the OS/host facts.

### Recipe kinds

| kind             | meaning                                            | may yield |
|------------------|----------------------------------------------------|-----------|
| `discovery`      | produces *knowledge only* (paths, versions, hashes) | —        |
| `service-access` | gains access to a service (e.g. FTP login)         | —        |
| `creds`          | obtains a usable credential/artifact               | —        |
| `foothold`       | obtains an interactive shell                       | user      |
| `privesc`        | escalates to root                                  | root      |

A step that yields the user flag must be a `foothold`; the root flag a `privesc`.
Credential *reuse* vs. default/common credentials is not a separate kind — it is
just a difference in `requires`, which the planner handles automatically.

### Two invariants the planner enforces

1. **Doability by construction** — a plan only exists if every precondition was
   met earlier, so a generated machine is doable by definition.
2. **Causal chain** — every step must consume something the previous step
   produced. This is what stops the generator from padding depth with pointless
   discovery steps or redundant parallel paths: if a requested depth has no real
   chain, generation fails instead of emitting filler.

## Flows it can build today

- **3 steps to user (FTP):** default FTP creds → leak SSH creds from the share →
  SSH foothold (`ftp-default-creds → ftp-config-leak-creds → ssh-creds-foothold`).
- **3 steps to user (web):** dir brute force → admin panel leaks creds → SSH.
- **2 steps to user:** exposed `.env` on the web server → SSH foothold.
- **1 step to user:** unauthenticated RCE → reverse shell (a legitimate one-step
  foothold, not a shortcut).
- **1 step to root:** `sudo` misconfiguration. **2 steps to root:** local
  enumeration finds a SUID binary → GTFOBins abuse.

## Usage

```bash
PYTHONPATH=src python3 -m boxes lint
PYTHONPATH=src python3 -m boxes recipes
PYTHONPATH=src python3 -m boxes gen --to-user 3 --to-root 2 --seed 42
PYTHONPATH=src python3 -m boxes gen --to-user 3 --to-root 2 --seed 42 --build-seed 2
PYTHONPATH=src python3 -m boxes gen --to-user 2 --to-root 1 --json

# recipe tooling
PYTHONPATH=src python3 -m boxes new my-sudo --kind privesc
PYTHONPATH=src python3 -m boxes test-recipe my-sudo
PYTHONPATH=src python3 -m boxes test-recipe --all
PYTHONPATH=src python3 -m boxes test-recipe ssh-creds-foothold --fixture
```

Or install it: `pip install -e .` then use `boxes ...`.

Run the tests with `python3 -m pytest`.

## Seeds

Two independent seeds:

- `--seed` picks the **plan** — which recipes, in what order.
- `--build-seed` materialises the **values inside** those recipes — usernames,
  passwords, filenames, chosen binaries.

If `--build-seed` is omitted it is chosen randomly, just like `--seed`; both
seeds are printed so the exact machine can be reproduced. Give both to get a
*family*: same attack path, different flavour.

```bash
PYTHONPATH=src python3 -m boxes gen --seed 42 --build-seed 1   # path A, flavour 1
PYTHONPATH=src python3 -m boxes gen --seed 42 --build-seed 2   # path A, flavour 2
```

Values are derived per `(build_seed, step instance, parameter)` rather than
drawn from one global stream. Plan variables are numbered by position
(`ftp-config-leak-creds#1.ssh_user`), so multiple credential sets in one plan
never collide. Recipe params can be `choice`, `password`, or `token` (for
randomised filenames/identifiers).

## Recipe tooling and the test harness

`boxes new <id> --kind <kind>` emits a `recipe.yaml` skeleton that already
passes lint and the harness, so you never start from a broken arity or a missing
field.

`boxes test-recipe <id>` tests a recipe **in isolation**, with no machine and no
VM. It:

- grounds the recipe's `params` with fixture values;
- builds a minimal state that satisfies its `requires`;
- applies the recipe and checks its `provides` come out fully grounded;
- renders the `walkthrough` and checks there are no unresolved `{placeholders}`;
- runs a **negative test**: without its non-prelude requirements the recipe must
  not apply (recipes that only need network exposure are warned, not failed).

`--fixture` prints the grounded fixture. That object is deliberate: it is the
minimal concrete input a recipe needs, so the *same fixture* will drive P1's
minimal-repro VM and real PoC run. It is the bridge from symbolic P0 to real
verification, and the thing a public recipe registry's CI would run on every
submission.

## Adding a recipe

Fastest path: `boxes new <id> --kind <kind>` scaffolds a valid recipe. Or write
`recipes/<id>/recipe.yaml` by hand. Minimum shape:

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
    type: choice         # choice | password
    values: ["/usr/bin/find"]
walkthrough: |
  ... uses `{binary}` and `{u}` ...
```

`boxes lint` will catch unknown predicates, wrong arity, unbound variables in
`provides`, a flag yielded by the wrong kind, and flags reachable with no real
work.

## P1 fast path: build + verify on containers

VMs need KVM (and this host has no nested virt), so the fast path runs recipes on
**containers** behind a pluggable backend interface:

- `backends/docker.py` — implemented, and what the CLI uses.
- `backends/fake.py` — in-memory, for unit tests.
- QEMU will implement the same interface later for kernel/boot-level recipes
  (`fidelity: vm`).

A base image is built once with network access; every machine container is then
created with `--network none`, so recipes never get egress at verify time.

```bash
# one-time (or after changing the Dockerfile)
PYTHONPATH=src python3 -m boxes image build --os ubuntu-22.04

# L2: prove one recipe in isolation
PYTHONPATH=src python3 -m boxes verify --recipe sudo-misconfig-privesc

# L2: every verifiable recipe
PYTHONPATH=src python3 -m boxes verify --all

# L3: build a whole machine and run the full chain
PYTHONPATH=src python3 -m boxes verify --machine --to-user 3 --to-root 2 --seed 0
```

All shipped recipes are verifiable, including the FTP → leaked creds → SSH
foothold chain and the web discovery → admin creds → SSH chain. The base image
carries `vsftpd`, `openssh-server`, `openssh-client` and `sshpass` for them.

### Recipe verification contract

A verifiable recipe declares a provision script and a PoC script:

```yaml
fidelity: container          # container | vm
provision: ./provision.sh    # runs as root; makes `requires` real
poc: ./poc.sh                # runs as the actor; exit 0 = proven
actor: $u                    # principal to run the PoC as (default: attacker)
poc_timeout: 120
```

Both scripts receive the grounded context as environment variables
(`BOX_U`, `BOX_BINARY`, `BOX_RECIPE`, `BOX_OS`, ...). The actor is resolved from
that context, so the PoC runs as the principal the step claims to act as — e.g.
the root step in a chain runs as the user the earlier foothold produced. That
is how the chain proves *composability*, not just isolated steps.

Scripts are arbitrary code. Today they run as root **inside** a
`--network none` container with memory/CPU/PID limits, which is acceptable for
trusted first-party recipes; a public registry must sandbox harder.

`boxes verify --machine` requires every recipe in the chain to have
provision+poc; otherwise it reports which ones are symbolic-only rather than
silently skipping them.

## Roadmap

| Stage | Scope | Status |
|-------|-------|--------|
| **P0** — symbolic generation | Facts + unification, typed predicates, recipes, bounded-length planner, `open_port` prelude, causal-chain constraint, two-seed manifest, lint, `boxes new` scaffold, per-recipe harness | **Done** |
| **P1** — container fast path | Pluggable backend (Docker + fake), base image, `provision`/`poc` contract, L2 minimal repro, L3 full-chain verification, real FTP/SSH/web/SUID/sudo recipes | **Done** |
| **P2** — fidelity + branching | QEMU backend for `fidelity: vm` (kernel/boot-level recipes), snapshots, multiple paths per flag (DAG instead of a chain), separate-place credentials (`creds.uname` + `creds.pass` consumed independently) | **Next** |
| **P3** — coherence + scale | Difficulty budgets, themes, typed choices (value sets constrained by what provision/PoC support), more distros, per-recipe verification caching and parallel runs | Planned |
| **P4** — registry | Recipe registry API + client, signed recipes, sandboxed recipe execution, per-recipe CI | Planned |

P1 delivered L3/manifest/flags earlier than originally planned, and swapped the
QEMU-first build for a container fast path because this host has no nested virt
(no `/dev/kvm`). QEMU remains the P2 backend for recipes that need a real kernel.
