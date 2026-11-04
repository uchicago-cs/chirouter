#!/usr/bin/env python3

# Prints the test categories in a rubric file.
#
# Usage: print-categories.py RUBRIC_FILE

import json
from typing import IO

import click

# Width of the separator lines
WIDTH = 80


@click.command(name="print-categories")
@click.argument('rubric_file', type=click.File())
def cmd(rubric_file: IO[str]) -> None:
    '''
    Prints the test categories in a rubric file.

    Inputs:
      rubric_file (file): the rubric file.

    Returns: nothing.
    '''
    rubric = json.load(rubric_file)

    print("=" * WIDTH)
    print(rubric["name"])
    for c in rubric["categories"]:
        for sc in c["subcategories"]:
            print(" - ", sc["cid"])

    print("=" * WIDTH)


if __name__ == "__main__":
    cmd()
