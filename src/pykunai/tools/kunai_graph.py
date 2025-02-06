import os
import shutil
import argparse
import sys
import json
import graphviz
import tempfile
import uuid

from pykunai.event import JqDict


def decode_logs(path):
    if path == "-":
        for line in map(lambda x: x.strip(), sys.stdin):
            yield JqDict(json.loads(line))
    else:
        with open(path, "r", encoding="utf8") as fd:
            for line in map(lambda x: x.strip(), fd):
                yield JqDict(json.loads(line))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Transform kunai logs to mermaid graph"
    )
    parser.add_argument("-o", "--output", type=str, required=True, help="Ouptut file")
    parser.add_argument("KUNAI_LOGS", default="-", help="Kunai logs. Default: stdin")

    args = parser.parse_args()

    g = KunaiGraph()
    g.from_iterator(decode_logs(args.KUNAI_LOGS))
    g.to_svg(args.output)


if __name__ == "__main__":
    main()
