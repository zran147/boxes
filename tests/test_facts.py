from boxes.facts import Fact, Var, parse_fact, subst_fact, unify, unify_fact, validate_fact


def test_parse_basic():
    f = parse_fact("open_port($h, 21)")
    assert f == Fact("open_port", (Var("h"), 21))


def test_parse_quoted_and_bare_strings():
    assert parse_fact('knows(path, "/admin.php")') == Fact("knows", ("path", "/admin.php"))
    assert parse_fact("knows(path, /admin.php)") == Fact("knows", ("path", "/admin.php"))


def test_parse_zero_arity():
    assert parse_fact("access_root()") == Fact("access_root", ())


def test_unify_variable():
    s = unify_fact(Fact("creds", ("ssh", Var("u"), Var("p"))),
                   Fact("creds", ("ssh", "deploy", "hunter2")), {})
    assert s == {"u": "deploy", "p": "hunter2"}


def test_unify_shared_variable_connects_facts():
    # the same variable appears twice -> the values must be consistent
    s = unify_fact(Fact("creds", (Var("s"), Var("u"), Var("p"))),
                   Fact("creds", (Var("s"), Var("u"), Var("p"))), {})
    assert s is not None
    assert unify_fact(Fact("creds", ("ssh", Var("x"))),
                      Fact("creds", ("ftp", "y")), {}) is None


def test_unify_predicate_mismatch():
    assert unify_fact(Fact("a", ()), Fact("b", ()), {}) is None


def test_subst_fact():
    out = subst_fact(Fact("creds", ("ssh", Var("u"), Var("p"))), {"u": "deploy", "p": "x"})
    assert out == Fact("creds", ("ssh", "deploy", "x"))


def test_validate_arity():
    validate_fact(Fact("creds", ("u", "p")))
    validate_fact(Fact("creds.uname", ("u",)))
    validate_fact(Fact("creds.pass", ("p",)))
    validate_fact(Fact("service_access", ("ftp",)))
    validate_fact(Fact("service_access", ("ftp", "u", "p")))
    bad = [
        Fact("creds", ("u",)),  # pair is exactly two args
        Fact("creds", ("u", "p", "extra")),
        Fact("creds.uname", ("u", "p")),
        Fact("service_access", ()),
    ]
    for fact in bad:
        try:
            validate_fact(fact)
        except ValueError:
            continue
        raise AssertionError(f"expected arity error for {fact}")


def test_parse_dotted_predicate():
    assert parse_fact("creds.uname($u)") == Fact("creds.uname", (Var("u"),))
    assert parse_fact("creds.pass($p)") == Fact("creds.pass", (Var("p"),))


def test_validate_unknown_predicate():
    try:
        validate_fact(Fact("nope", ()))
    except ValueError:
        return
    raise AssertionError("expected unknown-predicate error")
