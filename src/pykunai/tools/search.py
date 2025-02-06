#!/usr/bin/env python3

import argparse
import json
import sys
import logging
import re
import hashlib

from pykunai.event import Query, Event
from pykunai.utils import decode_events

logger = logging.Logger(__file__)


def sha256_file(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()


def main():
    parser = argparse.ArgumentParser(
        description="Helper script to easily search in Kunai logs"
    )
    parser.add_argument(
        "--no-recurse",
        action="store_false",
        help="Does a recursive search (goes to child processes as well)",
    )
    parser.add_argument(
        "-g", "--guids", type=str, help="Search by task_uuid (comma split)"
    )
    parser.add_argument(
        "-P", "--regexes", type=str, help="Search by regexp (comma split)"
    )
    parser.add_argument("-c", "--hashes", type=str, help="Search by hash (comma split)")
    parser.add_argument("-F", "--file", type=str, help="Hash file and search by hash")
    parser.add_argument(
        "-f",
        "--filters",
        type=str,
        help="Filters output to display or not (- prefix) some event ids. Example: --filter=-1,-2 would show all events except event with id 1 or 2",
    )
    parser.add_argument(
        "kunai_json_input", help="Input file in json line format or stdin with -"
    )

    args = parser.parse_args()

    query = Query(args.no_recurse)

    eg = decode_events(args.kunai_json_input)

    if args.guids:
        query.add_guids(args.guids.split(","))
    if args.hashes:
        query.add_hashes(args.hashes.split(","))
    if args.file:
        query.add_hashes([sha256_file(args.file)])
    if args.regexes:
        query.add_regexp(args.regexes.split(","))
    if args.filters:
        query.add_filters(args.filters.split(","))

    for event in eg:
        if query.match(event):
            print(event.json(), flush=True)


if __name__ == "__main__":
    main()
