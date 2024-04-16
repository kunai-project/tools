#!/usr/bin/env python

import os
import sys
import toml
import time
import json
import logging
import asyncio
import urllib3
import argparse
import ipaddress

from typing import *
from datetime import date, datetime, timezone, timedelta

from pymisp import PyMISP, MISPEvent, MISPAttribute

ALLOWED_TYPES = set([
    "md5",
    "sha1",
    "sha256",
    "domain",
    "hostname",
    "ip-dst",
])

def log(msg: str, level:str):
    print(f"{level}:{msg}", file=sys.stderr)

def info(msg: str):
    log(msg, "INFO")

def uuids_from_search(search):
    uuids = []
    for res in search:
        if isinstance(res, dict):
            uuids.append(res["uuid"])
        else:
            uuids.append(res.uuid)
    return uuids

def iocs_from_attributes(source: str, attributes: List[MISPAttribute]) -> List[dict]:
    iocs = []
    for a in attributes:
        if a.type in ALLOWED_TYPES:
            iocs.append({"uuid": a.uuid, "source": source, "value": a.value, "event_uuid": a.event_uuid})
    return iocs

def ioc_from_attribute(attr, source=""):
    return IOC(uuid=attr.uuid, guuid=attr.event_uuid, source=source, value=attr.value, type=attr.type)


def emit_attributes(misp: PyMISP, uuids: List[str]):
    for uuid in uuids:
        event = misp.get_event(uuid, pythonify=True)
        for attr in event.attributes:
            attr.event_uuid = uuid
            yield attr
        for o in event.objects:
            for attr in o.attributes:
                # here we modify attribute to add an extra field
                # being the uuid of the event it is defined in
                attr.event_uuid = uuid
                yield attr

def gen_kunai_iocs(misp: PyMISP, source:str, since: date, all: bool, tags=None):
    published = True if not all else None

    # search events to pull attributes from
    if since == None:
        index = misp.search_index(published=published, tags=tags)
    else:
        index = misp.search_index(published=published, timestamp=since, tags=tags)

    for attr in emit_attributes(misp, uuids_from_search(index)):
        for ioc in iocs_from_attributes(source, [attr]):
            yield ioc


if __name__ == "__main__":

    default_config = os.path.realpath(os.path.join(
        os.path.dirname(__file__), "config.toml"))

    parser = argparse.ArgumentParser(
        description="Tool pulling IoCs from a MISP instance and converting them to be loadable in Kunai")
    parser.add_argument("-c", "--config", default=default_config,
                        type=str, help=f"Configuration file. Default: {default_config}")
    parser.add_argument("-s", "--silent", action="store_true",
                        help="Silent HTTPS warnings")
    parser.add_argument("-l", "--last", type=int, default=1,
                        help="Process events updated the last days")
    parser.add_argument("-o", "--output", type=str, default="/dev/stdout", help="Output file")
    parser.add_argument("--overwrite", action="store_true",
                        help="Overwrite output file (default is to append)")
    parser.add_argument("--all", action="store_true",
                        help="Process all events, published and unpublished. By default only published events are processed.")
    parser.add_argument("--tags", type=str,
                        help="Comma separated list of (event tags) to pull iocs for")
    parser.add_argument("--wait", type=int, default=60,
                        help="Wait time in seconds between to runs in service mode")
    parser.add_argument("--service", action="store_true",
                        help="Run in service mode (i.e endless loop)")
    parser.add_argument("--source", type=str,
                        help="Name of the IOC source")

    args = parser.parse_args()

    # silent https warnings
    if args.silent:
        urllib3.disable_warnings()

    config = toml.load(open(args.config))

    misp_config = config["misp"]
    misp = PyMISP(url=misp_config["url"], key=misp_config["key"], ssl=misp_config["ssl"])

    # handling last option
    since = None
    if args.last is not None:
        since = (datetime.now() - timedelta(days=args.last)).date()
    
    # handling source option
    if args.source is None:
        args.source = misp_config["name"]
    
    tags = args.tags.split(",") if args.tags is not None else None

    cache = set()
    if args.output != "/dev/stdout" and not args.overwrite:
        if os.path.isfile(args.output):
            info(f"building cache from existing file: {args.output}")
            with open(args.output, "r") as fd:
                for line in fd:
                    ioc = json.loads(line)
                    cache.add(ioc["uuid"])

    open_mode = "w" if args.overwrite else "a"
    with open(args.output, "a") as fd:
        while True:
            for ioc in gen_kunai_iocs(misp, args.source, since, args.all, tags):
                if ioc["uuid"] not in cache:
                    print(json.dumps(ioc), file=fd)
                    cache.add(ioc["uuid"])
            info(f"number of iocs: {len(cache)}")
            if args.service:
                info(f"waiting {args.wait}s before next run")
                time.sleep(args.wait)
            else:
                break