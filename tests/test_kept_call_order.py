"""A call's result kept in a variable must not be folded past another call.

ASE's compiler is `bool ok = compilation.add_file(manifest); file_delete(
manifest); if (!ok)`. `file_delete` touches nothing `add_file` reads, so
no receiver test saw it, and the fold moved `add_file` into the `if` --
after the delete. The compiler could never compile. `bgt oracle`'s
`kept_result_then_another_call` is the same shape from source.

Synthetic inputs only.
"""

import os
import sys

TOOLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "tools")
sys.path.insert(0, TOOLS)

from nvgt.decompile import Atom, FuncDecompiler  # noqa: E402


def _fd(now, stmt_count, sites, flushed=(), effects=(), stmts=()):
    fd = object.__new__(FuncDecompiler)
    fd.invocation_sites = sites
    fd.flushed_calls = list(flushed)
    fd.effect_sites = set(effects)
    fd.stmt_texts = list(stmts)
    fd.stmt_count = stmt_count
    fd._pos = lambda: now
    return fd


KEPT = Atom("call", "compilation.add_file(m)")


def test_a_flushed_call_in_between_reorders():
    fd = _fd(332, 6, {KEPT.text: {296}, "file_delete(m)": {327}},
             flushed=[(327, "file_delete(m)")])
    assert fd._reorders_side_effects(KEPT, (298, 6))


def test_a_statement_call_with_no_result_reorders():
    fd = _fd(16, 2, {"first_effect()": {9}}, effects=[14],
             stmts=["second_effect();"])
    assert fd._reorders_side_effects(Atom("call", "first_effect()"), (11, 1))


def test_an_impure_call_inside_an_emitted_statement_reorders():
    fd = _fd(40, 3, {KEPT.text: {10}, "other.go()": {20}},
             stmts=["a();", "b();", "x = other.go();"])
    assert fd._reorders_side_effects(KEPT, (12, 2))


def test_nothing_written_out_in_between_does_not():
    # a call still on the stack belongs to the expression being built
    fd = _fd(40, 2, {KEPT.text: {10}, "other.go()": {20}})
    assert not fd._reorders_side_effects(KEPT, (12, 2))


def test_a_value_that_is_not_an_impure_call_does_not():
    fd = _fd(40, 3, {"other.go()": {20}}, effects=[20],
             stmts=["other.go();"])
    assert not fd._reorders_side_effects(Atom("call", "(a + b)"), (12, 2))


def test_calls_before_the_value_ran_do_not():
    fd = _fd(40, 3, {KEPT.text: {10}}, flushed=[(5, "early()")],
             effects=[4])
    assert not fd._reorders_side_effects(KEPT, (12, 2))
