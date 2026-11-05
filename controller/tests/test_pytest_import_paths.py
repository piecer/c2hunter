"""Keep test-helper imports usable without a launcher-supplied PYTHONPATH."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


@pytest.mark.parametrize("entrypoint", ["console", "module"])
@pytest.mark.parametrize("working_directory", ["root", "controller"])
@pytest.mark.parametrize("analysis_first", [False, True])
def test_test_helper_imports_in_clean_pytest_process(
    tmp_path: Path, entrypoint: str, working_directory: str, analysis_first: bool
) -> None:
    source_root = Path(__file__).resolve().parents[2]
    checkout = tmp_path / "checkout"
    for project in ("controller", "analysis"):
        tests = checkout / project / "tests"
        tests.mkdir(parents=True)
        for name in ("conftest.py", "__init__.py"):
            source = source_root / project / "tests" / name
            if source.exists():
                shutil.copyfile(source, tests / name)
        shutil.copyfile(source_root / project / "pyproject.toml", tests.parent / "pyproject.toml")
    worker = checkout / "sensor/worker/src/c2hunter_worker"
    worker.mkdir(parents=True)
    (worker / "__init__.py").write_text("VALUE = 43\n")
    (checkout / "controller/tests/shared_fixture.py").write_text("VALUE = 41\n")
    (checkout / "controller/tests/test_controller_import.py").write_text(
        "from pathlib import Path\n"
        "import os\n"
        "import shared_fixture as flat\n"
        "from tests import shared_fixture as packaged\n"
        "import c2hunter_worker as worker\n"
        "def test_both_import_styles():\n"
        "    expected = Path(__file__).with_name('shared_fixture.py')\n"
        "    assert Path(flat.__file__) == expected\n"
        "    assert Path(packaged.__file__) == expected\n"
        "    assert flat.VALUE == packaged.VALUE == 41\n"
        "    assert worker.VALUE == 43\n"
        "    assert Path(worker.__file__) == (\n"
        "        Path(__file__).parents[2] / 'sensor/worker/src/c2hunter_worker/__init__.py'\n"
        "    )\n"
        "    assert 'PYTHONPATH' not in os.environ\n"
    )
    (checkout / "analysis/tests/analysis_fixture.py").write_text("VALUE = 42\n")
    (checkout / "analysis/tests/test_analysis_import.py").write_text(
        "from analysis_fixture import VALUE\n"
        "def test_analysis_flat_import():\n"
        "    assert VALUE == 42\n"
    )
    home = tmp_path / "home"
    home.mkdir()
    env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PYTHONPATH", "PYTHONHOME", "PYTEST_ADDOPTS", "PYTEST_PLUGINS"}
    }
    env.update(HOME=str(home), PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONDONTWRITEBYTECODE="1")
    if entrypoint == "console":
        command = [str(Path(sys.executable).with_name("pytest"))]
    else:
        command = [sys.executable, "-I", "-B", "-m", "pytest"]
    projects = ["analysis", "controller"] if analysis_first else ["controller", "analysis"]
    command.extend(["-q", "--color=no", "--tb=short", "-p", "no:cacheprovider"])
    command.extend(str(checkout / project / "tests") for project in projects)
    cwd = checkout if working_directory == "root" else checkout / "controller"
    result = subprocess.run(
        command, cwd=cwd, env=env, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "2 passed" in result.stdout
