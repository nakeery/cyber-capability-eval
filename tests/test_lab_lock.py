"""The two modules that talk to real Docker hold the harness's lock (D-087).

The behavior itself (a second holder fails with "another harness is running") is `run_lock`'s, tested in
test_run.py. What can silently go wrong is the WIRING: a new Docker module, or an edit to a `pytestmark`, that
drops `lab_lock` would bring back the overlap this prevents, and no Docker-free test would notice.
"""

import pytest
import test_lab_docker
import test_run_docker

MODULES = [test_lab_docker, test_run_docker]


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__)
def test_a_real_docker_module_holds_the_harness_lock(module):
    marks = module.pytestmark
    assert any(m.name == "usefixtures" and "lab_lock" in m.args for m in marks), module.__name__


@pytest.mark.parametrize("module", MODULES, ids=lambda m: m.__name__)
def test_the_docker_skip_comes_before_the_lock(module):
    # Pytest applies marks in order; a skip listed after the lock would take it on a machine without Docker.
    names = [m.name for m in module.pytestmark]
    assert names.index("skipif") < names.index("usefixtures")


def test_every_module_that_builds_a_real_lab_is_covered():
    # The modules that import Lab and call `up` against real Docker. A new one has to be added to MODULES above.
    import pathlib
    here = pathlib.Path(__file__).parent
    real = {p.stem for p in here.glob("test_*.py")
            if "_docker_ready" in p.read_text(encoding="utf-8") and p.name != "test_lab_lock.py"}
    assert real == {m.__name__ for m in MODULES}
