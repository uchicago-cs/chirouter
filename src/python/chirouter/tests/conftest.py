# pytest configuration for the chirouter tests
#
# Defines the command-line options accepted by the tests, the hooks that
# select which tests to run (by category or rubric), and the
# chirouter_runner fixture used by all the tests.

import json
import os.path
from typing import Any

import pytest
from chirouter.tests import ChirouterTestRunner

# Categories in the rubric files specified with --chirouter-rubric
# (or None, if no rubric files were specified)
RUBRIC_CATEGORIES = pytest.StashKey[set[str] | None]()


def pytest_addoption(parser: pytest.Parser) -> None:
    '''
    Adds the chirouter command-line options (pytest hook).

    Inputs:
      parser (pytest.Parser): the command-line parser.

    Returns: nothing.
    '''
    parser.addoption("--chirouter-category", action="store",
                     metavar="CATEGORY_ID",
                     help="only run tests in category CATEGORY_ID.")
    parser.addoption("--chirouter-rubric", action="append",
                     metavar="RUBRIC_FILE",
                     help="only run the tests in this rubric file")
    parser.addoption("--chirouter-exe", action="store",
                     metavar="CHIROUTER_EXE", default="build/chirouter",
                     help="set location of chirouter executable")
    parser.addoption("--chirouter-loglevel", action="store", type=int,
                     default=0, metavar="LOGLEVEL",
                     help="set log level in chirouter to LOGLEVEL "
                          "(-1: -q, 0: normal, 1: -v, 2: -vv, 3: -vvv).")
    parser.addoption("--chirouter-port", action="store", type=int, default=-1,
                     help="port to run chirouter on "
                          "(use -1 to use a random port in each test)")
    parser.addoption("--chirouter-external-host", action="store", type=str,
                     default="localhost",
                     help="Do not launch chirouter, and instead connect to "
                          "chirouter on this host")
    parser.addoption("--chirouter-external-port", action="store", type=int,
                     help="Do not launch chirouter, and instead connect to "
                          "chirouter on this port")
    parser.addoption("--generate-alltests-file", action="store", type=str,
                     default=None,
                     help="Generate file with all the test categories "
                          "and names")


def pytest_sessionstart(session: pytest.Session) -> None:
    '''
    Loads the rubric files specified with --chirouter-rubric (pytest hook).

    Inputs:
      session (pytest.Session): the test session.

    Returns: nothing. Exits if a rubric file doesn't exist.
    '''
    session.stash[RUBRIC_CATEGORIES] = None
    rubric_files = session.config.option.chirouter_rubric
    if rubric_files is not None:
        rubric_categories: set[str] = set()
        session.stash[RUBRIC_CATEGORIES] = rubric_categories
        for rubric_file in rubric_files:
            if not os.path.exists(rubric_file):
                pytest.exit("No such rubric file: {}".format(rubric_file))

            with open(rubric_file) as f:
                rubric = json.load(f)
                for c in rubric["categories"]:
                    for sc in c["subcategories"]:
                        rubric_categories.add(sc["cid"])


def pytest_collection_finish(session: pytest.Session) -> None:
    '''
    Generates the file with all the test categories and names, if
    requested with --generate-alltests-file (pytest hook).

    Inputs:
      session (pytest.Session): the test session.

    Returns: nothing.
    '''
    alltests_file = session.config.option.generate_alltests_file
    if alltests_file is not None:
        with open(alltests_file, "w") as f:
            for item in session.items:
                category_marker = item.get_closest_marker("category")
                if category_marker is not None:
                    category = category_marker.args[0]
                    f.write("{},{}\n".format(category, item.nodeid))


def pytest_runtest_setup(item: pytest.Item) -> None:
    '''
    Skips the test if it is not in the category specified with
    --chirouter-category, or in the rubrics specified with
    --chirouter-rubric (pytest hook).

    Inputs:
      item (pytest.Item): the test.

    Returns: nothing.
    '''
    rubric_categories = item.session.stash[RUBRIC_CATEGORIES]
    only_category = item.config.getoption("--chirouter-category")
    if only_category is None and rubric_categories is None:
        return

    category_marker = item.get_closest_marker("category")
    if category_marker is None:
        return

    category = category_marker.args[0]
    if only_category is not None and category != only_category:
        pytest.skip("Only running tests in category {}"
                    .format(only_category))
    elif rubric_categories is not None and category not in rubric_categories:
        pytest.skip("Only running tests in categories {}"
                    .format(", ".join(rubric_categories)))


def pytest_json_runtest_metadata(item: pytest.Item,
                                 call: pytest.CallInfo[None]) -> dict[str, Any]:
    '''
    Adds the category of each test to the JSON report (pytest-json-report
    hook), so grade.py can compute the score of each category.

    Inputs:
      item (pytest.Item): the test.
      call (pytest.CallInfo): information about the test run.

    Returns:
      (dict) the metadata to add to the test's entry in the report.
    '''
    marker = item.get_closest_marker("category")
    if marker is None:
        return {}
    return {'category': marker.args[0]}


@pytest.fixture
def chirouter_runner(request: pytest.FixtureRequest) -> ChirouterTestRunner:
    '''
    Fixture that provides each test with a ChirouterTestRunner (which
    is ended when the test finishes).

    Inputs:
      request (pytest.FixtureRequest): the fixture request.

    Returns:
      (ChirouterTestRunner) the test runner (already started).
    '''
    config = request.config
    runner = ChirouterTestRunner(
        chirouter_exe=config.getoption("--chirouter-exe"),
        chirouter_port=config.getoption("--chirouter-port"),
        loglevel=config.getoption("--chirouter-loglevel"),
        chirouter_host=config.getoption("--chirouter-external-host"),
        external_chirouter_port=config.getoption("--chirouter-external-port"))

    runner.start()
    request.addfinalizer(runner.end)

    return runner
