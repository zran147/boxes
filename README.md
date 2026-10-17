# boxes

A procedural generator for HTB-style vulnerable machines. You ask for a number
of steps to the user flag and a number of further steps to the root flag, and it
generates a machine: a random-but-coherent chain of exploits, each drawn from a
library of "recipes".

**This is P0: plan-only.** It reasons about machines symbolically and prints a
walkthrough. No VMs are built or verified yet (that's P1+).

## Concepts

- **Fact** — a typed atom describing world state, e.g. `net.port(target, 22)`,
  `creds(ssh, deploy, hunter2)`, `access_shell(deploy)`. Predicate arities are
  declared in `facts.SIGNATURES`; this is the *typed context*.
- **Recipe** — an operator: `requires` (preconditions), `provides` (effects),
  randomizable `params`, and a `walkthrough` template. A recipe is a *template*;
  its params are grounded per-machine.
- **Plan** — an ordered chain of recipe applications where every `requires` is
  satisfied by an earlier `provides`.
- **Manifest** — the concrete values (passwords, usernames, chosen binaries)
  produced from a seed. The manifest is what guarantees a password leaked in one
  step is exactly the one consumed by a later step.
- **Prelude** — things that are free and not steps: `nmap` (which reveals
  `net.port` facts) and the OS/host facts.

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
PYTHONPATH=src python3 -m boxes gen --to-user 2 --to-root 1 --json

# recipe tooling
PYTHONPATH=src python3 -m boxes new my-sudo --kind privesc
PYTHONPATH=src python3 -m boxes test-recipe my-sudo
PYTHONPATH=src python3 -m boxes test-recipe --all
PYTHONPATH=src python3 -m boxes test-recipe ssh-creds-foothold --fixture
```

Or install it: `pip install -e .` then use `boxes ...`.

Run the tests with `python3 -m pytest`.

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

## Not done yet (P1+)

- Build layer: QEMU + qcow2 overlays (or Incus/LXD for recipes that don't need a
  custom kernel); provisioning over SSH; flags; snapshots.
- Verification: L2 minimal-repro per recipe (cached, parallel) and L3 full-chain
  runs; POСs run against the built VM.
- Difficulty budgets and themes for coherence; multiple paths per flag (DAG
  instead of a chain); more distros.
- Registry API + signed recipes + sandboxed recipe execution.
