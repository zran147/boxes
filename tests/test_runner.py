from dataclasses import dataclass

from boxes.backends import FakeBackend
from boxes.backends.base import ExecResult
from boxes.facts import parse_fact
from boxes.harness import Fixture
from boxes.recipe import Recipe
from boxes.runner import build_env, resolve_actor, verify_machine, verify_paths, verify_recipe


def make_recipe(tmp_path, rid, *, actor=None, provision=True, poc=True, requires=None, poc_backend="container"):
    d = tmp_path / rid
    d.mkdir()
    prov = None
    p = None
    if provision:
        (d / "provision.sh").write_text("echo provisioning\n")
        prov = "provision.sh"
    if poc:
        (d / "poc.sh").write_text("echo proving\n")
        p = "poc.sh"
    return Recipe(
        id=rid,
        version="1.0.0",
        kind="privesc",
        os=["ubuntu-*"],
        difficulty=0.2,
        requires=requires or [parse_fact("access_shell($u)")],
        provides=[parse_fact("access_root()")],
        yields=["root"],
        params={},
        walkthrough="",
        provision=prov,
        poc=p,
        actor=actor,
        poc_backend=poc_backend,
        path=d / "recipe.yaml",
    )


def fixture(**ctx) -> Fixture:
    return Fixture(
        recipe_id="r",
        os="ubuntu-22.04",
        params={},
        requires=[],
        provides=[],
        walkthrough="",
        context={"os": "ubuntu-22.04", **ctx},
    )


def test_env_keys_are_sanitised():
    r = Recipe(
        id="r", version="1.0.0", kind="discovery", os=["ubuntu-*"], difficulty=0.1,
        requires=[parse_fact("open_port($h, 80)")], provides=[parse_fact("knows(a, $v)")],
        yields=[], params={}, walkthrough="",
    )
    env = build_env(r, {"a.b": "x", "u": "deploy"}, "ubuntu-22.04")
    assert env["BOX_A_B"] == "x"
    assert env["BOX_U"] == "deploy"
    assert env["BOX_RECIPE"] == "r"
    assert env["BOX_OS"] == "ubuntu-22.04"


def test_actor_resolution():
    rec = Recipe(
        id="r", version="1.0.0", kind="privesc", os=["ubuntu-*"], difficulty=0.1,
        requires=[parse_fact("access_shell($u)")], provides=[parse_fact("access_root()")],
        yields=["root"], params={}, walkthrough="", actor="$u",
    )
    assert resolve_actor(rec, {"u": "deploy"}) == "deploy"
    rec.actor = None
    assert resolve_actor(rec, {}) == "attacker"


def test_verify_recipe_provisions_as_root_then_pocs_as_actor(tmp_path):
    rec = make_recipe(tmp_path, "sudo-ish", actor="$u")
    backend = FakeBackend()

    result = verify_recipe(rec, fixture(u="deploy"), backend, "img:test")

    assert result.ok
    execs = [c for c in backend.calls if c[0] == "exec"]
    assert [e[3] for e in execs] == [None, "deploy"]  # provision as root, poc as actor
    assert execs[0][4]["BOX_U"] == "deploy"
    assert backend.destroyed == [result.container]


def test_verify_recipe_tears_down_on_failure(tmp_path):
    rec = make_recipe(tmp_path, "boom", actor="$u")

    def responder(name, script, user, env):
        return ExecResult(1, "", "nope") if "proving" in script else ExecResult(0, "", "")

    backend = FakeBackend(responder=responder)
    result = verify_recipe(rec, fixture(u="deploy"), backend, "img:test")

    assert not result.ok
    assert backend.destroyed == [result.container]
    assert any(s.phase == "poc" and not s.ok for s in result.steps)


def test_verify_recipe_refuses_symbolic_only(tmp_path):
    rec = make_recipe(tmp_path, "symbolic", provision=False, poc=False)
    backend = FakeBackend()
    result = verify_recipe(rec, fixture(), backend, "img:test")
    assert not result.ok
    assert "provision/poc" in result.error
    assert backend.calls == []


@dataclass
class _Step:
    recipe: Recipe


@dataclass
class _Plan:
    os_name: str
    steps: list
    seed: int


class _Manifest:
    def __init__(self, contexts):
        self.contexts = contexts

    def step_context(self, step):
        return self.contexts[step.recipe.id]


def test_verify_machine_provisions_all_then_runs_pocs_in_order(tmp_path):
    r1 = make_recipe(tmp_path, "foothold-ish")
    r1.yields = ["user"]
    r2 = make_recipe(tmp_path, "privesc-ish", actor="$u")
    plan = _Plan("ubuntu-22.04", [_Step(r1), _Step(r2)], seed=1)
    manifest = _Manifest({"foothold-ish": {"u": "www-data"}, "privesc-ish": {"u": "www-data"}})
    backend = FakeBackend()

    result = verify_machine(plan, manifest, backend, "img:test")

    assert result.ok
    execs = [c for c in backend.calls if c[0] == "exec"]
    assert len(execs) == 4
    # all provisioning first, then all PoCs
    assert all("provisioning" in e[2] for e in execs[:2])
    assert all("proving" in e[2] for e in execs[2:])
    assert [e[3] for e in execs] == [None, None, "attacker", "www-data"]
    assert backend.destroyed == [result.container]


def test_verify_machine_refuses_when_a_step_is_symbolic(tmp_path):
    r1 = make_recipe(tmp_path, "ok")
    r2 = make_recipe(tmp_path, "symbolic", provision=False, poc=False)
    plan = _Plan("ubuntu-22.04", [_Step(r1), _Step(r2)], seed=1)
    backend = FakeBackend()

    result = verify_machine(plan, _Manifest({}), backend, "img:test")

    assert not result.ok
    assert "without provision/poc" in result.error
    assert backend.calls == []


def test_vm_recipe_is_rejected_by_a_container_backend(tmp_path):
    rec = make_recipe(tmp_path, "kernel-thing", poc_backend="vm")
    backend = FakeBackend()
    result = verify_recipe(rec, fixture(u="x"), backend, "img:test")
    assert not result.ok
    assert "no PoC for the container backend" in result.error
    assert backend.calls == []


def test_missing_actor_is_reported_not_raised(tmp_path):
    rec = make_recipe(tmp_path, "bad-actor", actor="$nope")
    result = verify_recipe(rec, fixture(u="x"), FakeBackend(), "img:test")
    assert not result.ok
    assert any("not bound" in s.output for s in result.steps)


def test_reserved_env_keys_win_over_params():
    rec = Recipe(
        id="r", version="1.0.0", kind="discovery", os=["ubuntu-*"], difficulty=0.1,
        requires=[parse_fact("open_port($h, 80)")], provides=[parse_fact("knows(a, $v)")],
        yields=[], params={}, walkthrough="",
    )
    env = build_env(rec, {"recipe": "nope", "os": "nope"}, "ubuntu-22.04")
    assert env["BOX_RECIPE"] == "r"
    assert env["BOX_OS"] == "ubuntu-22.04"


def test_attacker_context_runs_the_poc_in_the_attacker_container(tmp_path):
    rec = make_recipe(tmp_path, "net-poc", actor="$u")
    rec.poc_context = "attacker"
    backend = FakeBackend()

    result = verify_recipe(rec, fixture(u="deploy"), backend, "img:test")

    assert result.ok
    creates = [c for c in backend.calls if c[0] == "create"]
    assert len(creates) == 2  # target + attacker
    kinds = [c[0] for c in backend.calls]
    assert kinds.count("network_create") == 1
    assert kinds.count("network_destroy") == 1

    execs = [c for c in backend.calls if c[0] == "exec" and c[4]]
    assert execs[0][3] is None  # provision as root in the target
    assert execs[1][3] == "attacker"
    assert execs[1][4]["BOX_HOST"] == "target"


def test_machine_shares_one_attacker_container_across_the_chain(tmp_path):
    r1 = make_recipe(tmp_path, "net-one")
    r1.poc_context = "attacker"
    r2 = make_recipe(tmp_path, "net-two", actor="$u")
    r2.poc_context = "attacker"

    plan = _Plan("ubuntu-22.04", [_Step(r1), _Step(r2)], seed=1)
    manifest = _Manifest({"net-one": {}, "net-two": {"u": "www-data"}})
    backend = FakeBackend()

    result = verify_machine(plan, manifest, backend, "img:test")

    assert result.ok
    creates = [c for c in backend.calls if c[0] == "create"]
    assert len(creates) == 2  # exactly one target + one shared attacker
    attacker = [c[1] for c in creates if c[4] is None][0]
    poc_execs = [c for c in backend.calls if c[0] == "exec" and "proving" in c[2]]
    assert len(poc_execs) == 2
    assert all(c[1] == attacker for c in poc_execs)
    assert all(c[4]["BOX_HOST"] == "target" for c in poc_execs)


def test_container_names_stay_within_the_dns_hostname_limit():
    from boxes.runner import _container_name

    for rid in ["a" * 120, "x" * 60, "normal-id"]:
        for role in ("target", "attacker"):
            assert len(_container_name(role, rid)) <= 63



def test_vm_attacker_network_failure_is_a_warning_not_a_crash(tmp_path, monkeypatch):
    import boxes.runner as runner
    from boxes.backends.base import ExecResult

    class FailingNet(FakeBackend):
        fidelity = "vm"

        def network_create(self, name, attacker_pid=None):
            return ExecResult(1, "", "sudo: a password is required")

    rec = make_recipe(tmp_path, "vm-net", poc_backend="vm")
    rec.poc_context = "attacker"

    monkeypatch.setattr(runner, "_attacker_backend", lambda backend: FakeBackend())
    result = verify_recipe(rec, fixture(u="x", p="y"), FailingNet(), "img:test")

    assert not result.ok
    assert "warning:" in result.error
    assert "cannot be verified" in result.error


class FakeVMSnap(FakeBackend):
    fidelity = "vm"

    def __init__(self):
        super().__init__()
        self.snapshots = []
        self.restores = []
        self.seals = []

    def snapshot(self, name, label):
        self.snapshots.append(label)
        return ExecResult(0, "", "")

    def restore(self, name, label):
        self.restores.append(label)
        return ExecResult(0, "", "")

    def seal(self, name):
        self.seals.append(name)
        return ExecResult(0, "", "")


def _vm_recipe(tmp_path, rid):
    d = tmp_path / rid
    d.mkdir()
    (d / "provision.sh").write_text(f"echo provision-{rid}\n")
    (d / "poc.sh").write_text(f"echo poc-{rid}\n")
    return Recipe(
        id=rid, version="1.0.0", kind="privesc", os=["ubuntu-*"], difficulty=0.1,
        requires=[parse_fact("open_port($h, 80)")],
        provides=[parse_fact("access_root()")], yields=["root"],
        params={}, walkthrough="", provision="provision.sh",
        poc="poc.sh", poc_backend="vm", poc_context="target",
        path=d / "recipe.yaml",
    )


def _vm_plan(recipe):
    from boxes.planner import Plan, Step

    return Plan(
        "ubuntu-22.04",
        [Step(recipe, f"{recipe.id}#0", {}, recipe.requires, recipe.provides, [])],
        1,
    )


class _Ctx:
    def step_context(self, step):
        return {"os": "ubuntu-22.04"}


def test_vm_machine_snapshots_before_pocs_and_restores_after(tmp_path, monkeypatch):
    import boxes.runner as runner

    monkeypatch.setattr(runner.proxy_mod, "is_up", lambda: False)
    rec = _vm_recipe(tmp_path, "vm-only")
    backend = FakeVMSnap()

    result = verify_machine(_vm_plan(rec), _Ctx(), backend, "img:test")

    assert result.ok
    assert backend.snapshots == ["pre-poc"]
    assert backend.restores == ["pre-poc"]
    assert any(s.phase == "snapshot" for s in result.steps)


def test_verify_paths_uses_one_vm_and_snapshots_per_path(tmp_path, monkeypatch):
    import boxes.runner as runner

    monkeypatch.setattr(runner.proxy_mod, "is_up", lambda: False)
    r1 = _vm_recipe(tmp_path, "path-one")
    r2 = _vm_recipe(tmp_path, "path-two")
    backend = FakeVMSnap()

    results = verify_paths(
        [_vm_plan(r1), _vm_plan(r2)],
        [_Ctx(), _Ctx()],
        backend,
        "img:test",
    )

    assert len(results) == 2
    assert all(r.ok for r in results)
    assert len([c for c in backend.calls if c[0] == "create"]) == 1
    assert backend.snapshots == ["clean", "shared", "pre-poc", "pre-poc"]
    assert backend.restores == ["pre-poc", "shared", "pre-poc"]


def test_verify_paths_provisions_the_shared_prefix_once(tmp_path, monkeypatch):
    import boxes.runner as runner
    from boxes.planner import Plan, Step

    monkeypatch.setattr(runner.proxy_mod, "is_up", lambda: False)
    prefix = _vm_recipe(tmp_path, "prefix")
    root_a = _vm_recipe(tmp_path, "root-a")
    root_b = _vm_recipe(tmp_path, "root-b")

    shared = Step(prefix, "prefix#0", {}, prefix.requires, prefix.provides, [])
    plan_a = Plan("ubuntu-22.04", [shared, Step(root_a, "root-a#1", {}, root_a.requires, root_a.provides, [])], 1)
    plan_b = Plan("ubuntu-22.04", [shared, Step(root_b, "root-b#1", {}, root_b.requires, root_b.provides, [])], 2)
    backend = FakeVMSnap()

    results = verify_paths([plan_a, plan_b], [_Ctx(), _Ctx()], backend, "img:test")

    assert len(results) == 2
    assert all(r.ok for r in results)
    assert len([c for c in backend.calls if c[0] == "create"]) == 1
    provisions = [c for c in backend.calls if c[0] == "exec" and c[3] is None]
    assert len([c for c in provisions if "provision-prefix" in c[2]]) == 1
    assert backend.snapshots == ["clean", "shared", "pre-poc", "pre-poc"]
    assert backend.restores == ["pre-poc", "shared", "pre-poc"]
