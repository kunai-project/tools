import sys
import json
import hashlib

from typing import Generator
from .event import Event, JqDict


def decode_events(path: str) -> Generator[JqDict, None, None]:
    if path == "-":
        for line in map(lambda x: x.strip(), sys.stdin):
            yield Event(JqDict(json.loads(line)))
    else:
        with open(path, "r", encoding="utf8") as fd:
            for line in map(lambda x: x.strip(), fd):
                yield Event(JqDict(json.loads(line)))


def sha256_file(file_path: str) -> str:
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)

    return sha256.hexdigest()
