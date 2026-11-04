#!/usr/bin/env python3

# Computes the score of a test run.
#
# Reads the JSON report produced by pytest-json-report (tests.json, by
# default) and one or more rubric files, and prints a score report (or,
# with --gradescope, writes the results in the format expected by
# Gradescope).
#
# Usage: grade.py [--report-file FILE] [--gradescope FILE] RUBRIC_FILE...

from __future__ import annotations

import json
import sys
from collections import OrderedDict
from typing import IO, Any, NoReturn

import click

# Width of the score report
REPORT_WIDTH = 73


class Subcategory:
    '''
    A subcategory of tests in a rubric (identified by a category ID, which
    is the category specified in each test with @pytest.mark.category)
    '''

    def __init__(self, assignment: Assignment, cid: str,
                 expected_num_tests: int) -> None:
        '''
        Constructor

        Inputs:
          assignment (Assignment): the assignment the subcategory belongs to.
          cid (str): category ID.
          expected_num_tests (int): number of tests in the subcategory.
        '''
        self.assignment = assignment
        self.cid = cid
        self.expected_num_tests = expected_num_tests
        self.actual_num_tests = 0
        self.passed_tests = 0


class Category:
    '''
    A category of tests in a rubric (with one or more subcategories)
    '''

    def __init__(self, name: str, points: float) -> None:
        '''
        Constructor

        Inputs:
          name (str): name of the category.
          points (float): points for the category.
        '''
        self.name = name
        self.points = points
        self.subcategories: OrderedDict[str, Subcategory] = OrderedDict()

    @property
    def num_tests(self) -> int:
        '''
        The number of tests in the category
        '''
        return sum(sc.expected_num_tests for sc in self.subcategories.values())

    @property
    def passed_tests(self) -> int:
        '''
        The number of tests in the category that passed
        '''
        return sum(sc.passed_tests for sc in self.subcategories.values())

    @property
    def points_obtained(self) -> float:
        '''
        The points obtained in the category
        '''
        return (self.passed_tests / self.num_tests) * self.points


class Assignment:
    '''
    An assignment (the contents of a rubric file)
    '''

    def __init__(self, name: str, points: float) -> None:
        '''
        Constructor

        Inputs:
          name (str): name of the assignment.
          points (float): total points of the assignment.
        '''
        self.name = name
        self.points = points
        self.categories: OrderedDict[str, Category] = OrderedDict()
        self.subcategories: OrderedDict[str, Subcategory] = OrderedDict()

    @property
    def points_obtained(self) -> float:
        '''
        The points obtained in the assignment
        '''
        return sum(c.points_obtained for c in self.categories.values())


class GradingError(Exception):
    '''
    An error that prevents the tests from being graded
    '''
    pass


def load_rubrics(rubric_files: tuple[IO[str], ...]) -> tuple[
        list[Assignment], dict[str, Subcategory]]:
    '''
    Loads the rubric files.

    Inputs:
      rubric_files (tuple of files): the rubric files.

    Returns:
      (list of Assignment, dict) the assignments in the rubric files,
      and all their subcategories (indexed by category ID). Raises a
      GradingError if a subcategory appears more than once.
    '''
    assignments: list[Assignment] = []
    subcategories: dict[str, Subcategory] = {}

    for rubric_file in rubric_files:
        rubric = json.load(rubric_file)
        assignment = Assignment(rubric["name"], rubric["total_points"])

        for c in rubric["categories"]:
            category = Category(c["name"], c["points"])

            for sc in c["subcategories"]:
                if sc["cid"] in subcategories:
                    raise GradingError(f"Repeated subcategory: {sc['cid']}")

                subcategory = Subcategory(assignment, sc["cid"],
                                          sc["num_tests"])
                category.subcategories[subcategory.cid] = subcategory
                assignment.subcategories[subcategory.cid] = subcategory

                subcategories[sc["cid"]] = subcategory

            assignment.categories[category.name] = category

        assignments.append(assignment)

    return assignments, subcategories


def count_results(report_file: IO[str],
                  subcategories: dict[str, Subcategory]) -> None:
    '''
    Counts how many tests ran (and passed) in each subcategory.

    Inputs:
      report_file (file): the JSON report produced by pytest-json-report.
      subcategories (dict): the subcategories (indexed by category ID).
        Their actual_num_tests and passed_tests attributes are updated.

    Returns: nothing. Raises a GradingError if the report file is not
    correct.
    '''
    try:
        results = json.load(report_file)
    except (OSError, ValueError):
        raise GradingError("Error reading test results!")

    for test in results["tests"]:
        if "metadata" not in test:
            raise GradingError(
                "ERROR: Incorrect JSON report file (missing metadata)")

        cid = test["metadata"]["category"]
        if cid in subcategories:
            subcategories[cid].actual_num_tests += 1

            if test["outcome"] == "passed":
                subcategories[cid].passed_tests += 1


def write_gradescope_results(assignments: list[Assignment],
                             gradescope: str) -> None:
    '''
    Writes the results in the format expected by Gradescope.

    Inputs:
      assignments (list of Assignment): the graded assignments.
      gradescope (str): path of the file to write.

    Returns: nothing.
    '''
    gradescope_json: dict[str, Any] = {}
    gradescope_json["tests"] = []

    total_points_obtained = 0.0
    for assignment in assignments:
        for c in assignment.categories.values():
            gs_test: dict[str, Any] = {}
            gs_test["score"] = c.points_obtained
            gs_test["max_score"] = c.points
            gs_test["name"] = c.name

            total_points_obtained += c.points_obtained

            gradescope_json["tests"].append(gs_test)

    gradescope_json["score"] = total_points_obtained
    gradescope_json["visibility"] = "visible"
    gradescope_json["stdout_visibility"] = "visible"

    with open(gradescope, "w") as file:
        json.dump(gradescope_json, file, indent=2)


def write_empty_gradescope_results(gradescope: str) -> None:
    '''
    Writes Gradescope results with a score of zero (used when the tests
    could not be graded).

    Inputs:
      gradescope (str): path of the file to write.

    Returns: nothing.
    '''
    gradescope_json: dict[str, Any] = {}
    gradescope_json["score"] = 0.0
    gradescope_json["output"] = ("We were unable to run the tests due to "
                                 "an error in your code.")
    gradescope_json["visibility"] = "visible"
    gradescope_json["stdout_visibility"] = "visible"

    with open(gradescope, "w") as file:
        json.dump(gradescope_json, file, indent=2)


def print_report(assignments: list[Assignment]) -> None:
    '''
    Prints the score report.

    Inputs:
      assignments (list of Assignment): the graded assignments.

    Returns: nothing.
    '''
    total_points_obtained = 0.0
    total_points_possible = 0.0
    for assignment in assignments:
        print(assignment.name)
        print("=" * REPORT_WIDTH)
        print("%-35s %-6s / %-10s  %-6s / %-10s"
              % ("Category", "Passed", "Total", "Score", "Points"))
        print("-" * REPORT_WIDTH)
        for c in assignment.categories.values():
            print("%-35s %-6i / %-10i  %-6.2f / %-10.2f"
                  % (c.name, c.passed_tests, c.num_tests,
                     c.points_obtained, c.points))
        print("-" * REPORT_WIDTH)
        print("%54s = %-6.2f / %-10i"
              % ("TOTAL", assignment.points_obtained, assignment.points))
        print("=" * REPORT_WIDTH)
        print()

        total_points_obtained += assignment.points_obtained
        total_points_possible += assignment.points

    if len(assignments) > 1:
        print(f"{'GRAND TOTAL':>54} = {total_points_obtained:-6.2f} / "
              f"{total_points_possible}")


@click.command(name="grade")
@click.argument('rubric_files', type=click.File(), nargs=-1)
@click.option("--report-file", type=click.File(), default="tests.json")
@click.option("--gradescope", type=click.Path())
def cmd(rubric_files: tuple[IO[str], ...], report_file: IO[str],
        gradescope: str | None) -> None:
    '''
    Computes the score of a test run (see the top of this file).

    Inputs:
      rubric_files (tuple of files): the rubric files.
      report_file (file): the JSON report produced by pytest-json-report.
      gradescope (str | None): if not None, write the results to this
        file, in the format expected by Gradescope.

    Returns: nothing.
    '''
    def fail(msg: str) -> NoReturn:
        '''
        Prints an error message and exits (writing a score of zero to the
        Gradescope results file, if one was specified).

        Inputs:
          msg (str): the error message.
        '''
        print(msg, file=sys.stderr)

        if gradescope is not None:
            write_empty_gradescope_results(gradescope)
            sys.exit(0)
        else:
            sys.exit(1)

    try:
        assignments, subcategories = load_rubrics(rubric_files)
        count_results(report_file, subcategories)
    except GradingError as e:
        fail(str(e))

    if gradescope is not None:
        write_gradescope_results(assignments, gradescope)
    else:
        print_report(assignments)


if __name__ == "__main__":
    cmd()
