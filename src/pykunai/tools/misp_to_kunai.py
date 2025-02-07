import os
import sys
import time
import json
import argparse

from typing import List
from datetime import date, datetime, timedelta

import requests
import toml
import urllib3
from pymisp import PyMISP, MISPEvent, MISPAttribute

TYPES_SEVERITY = {
    "md5": 10,
    "sha1": 10,
    "sha256": 10,
    "domain": 7,
    "hostname": 7,
    "ip-dst": 5,
    "path": 7,
}

REQUEST_TIMEOUT = 10


def log(msg: str, level: str):
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
        if a.object_relation in TYPES_SEVERITY:
            iocs.append(
                {
                    "type": a.object_relation,
                    "uuid": a.uuid,
                    "source": source,
                    "value": a.value,
                    "event_uuid": a.event_uuid,
                    "severity": TYPES_SEVERITY[a.object_relation],
                }
            )

        if a.type in TYPES_SEVERITY:
            iocs.append(
                {
                    "type": a.type,
                    "uuid": a.uuid,
                    "source": source,
                    "value": a.value,
                    "event_uuid": a.event_uuid,
                    "severity": TYPES_SEVERITY[a.type],
                }
            )
    return iocs


def emit_attributes(py_misp: PyMISP, uuids: List[str]):
    for uuid in uuids:
        event = py_misp.get_event(uuid, pythonify=True)
        for attr in event_emit_attributes(event):
            yield attr


def event_emit_attributes(event: MISPEvent):
    for attr in event.attributes:
        attr.event_uuid = event.uuid
        yield attr
    for o in event.objects:
        for attr in o.attributes:
            # here we modify attribute to add an extra field
            # being the uuid of the event it is defined in
            attr.event_uuid = event.uuid
            yield attr


def gen_kunai_iocs(
    py_misp: PyMISP, source: str, since: date, unpublished: bool, tags=None, to_ids=True
):
    published = True if not unpublished else None

    # search events to pull attributes from
    if since is None:
        index = py_misp.search_index(published=published, tags=tags)
    else:
        index = py_misp.search_index(published=published, timestamp=since, tags=tags)

    for attr in emit_attributes(py_misp, uuids_from_search(index)):
        if to_ids and not attr.to_ids:
            continue
        for ioc in iocs_from_attributes(source, [attr]):
            yield ioc


def kunai_iocs_from_feed(feed_config: dict, since: date):
    url = feed_config["url"].rstrip("/")
    if not url.endswith("manifest.json"):
        manifest_url = f"{url}/manifest.json"

    manifest = requests.get(manifest_url, timeout=REQUEST_TIMEOUT).json()

    for event_uuid in manifest:
        event_ts = datetime.fromtimestamp(manifest[event_uuid]["timestamp"]).date()
        if event_ts < since:
            continue
        event = requests.get(f"{url}/{event_uuid}.json", timeout=REQUEST_TIMEOUT).json()
        me = MISPEvent()
        me.from_dict(**event)
        for attr in event_emit_attributes(me):
            for ioc in iocs_from_attributes(feed_config["name"], [attr]):
                yield ioc


def main():
    default_config = os.path.realpath(
        os.path.join(os.path.dirname(__file__), "config.toml")
    )

    parser = argparse.ArgumentParser(
        description="Tool pulling IoCs from a MISP instance and converting them to be loadable in Kunai"
    )
    parser.add_argument(
        "-c",
        "--config",
        default=default_config,
        type=str,
        help=f"Configuration file. Default: {default_config}",
    )
    parser.add_argument(
        "-s", "--silent", action="store_true", help="Silent HTTPS warnings"
    )
    parser.add_argument(
        "-l", "--last", type=int, default=1, help="Process events updated the last days"
    )
    parser.add_argument(
        "-o", "--output", type=str, default="/dev/stdout", help="Output file"
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Overwrite output file (default is to append)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Process all events, published and unpublished. By default only published events are processed.",
    )
    parser.add_argument(
        "--tags", type=str, help="Comma separated list of (event tags) to pull iocs for"
    )
    parser.add_argument(
        "--no-to-ids",
        action="store_false",
        help="Also retrieve attributes with no MISP IDS flag. The default behaviour is to take only attributes with IDS flag",
    )
    parser.add_argument(
        "--wait",
        type=int,
        default=60,
        help="Wait time in seconds between to runs in service mode",
    )
    parser.add_argument(
        "--service", action="store_true", help="Run in service mode (i.e endless loop)"
    )

    args = parser.parse_args()

    # silent https warnings
    if args.silent:
        urllib3.disable_warnings()

    # checking for configuration file
    if not os.path.isfile(args.config):
        parser.error(f"no such file or directory: {args.config}")

    config = toml.load(open(args.config, encoding="utf-8"))

    misp_config = config["misp"]

    if misp_config["enable"] is True:
        misp = PyMISP(
            url=misp_config["url"], key=misp_config["key"], ssl=misp_config["ssl"]
        )

    # handling last option
    since = None
    if args.last is not None:
        since = (datetime.now() - timedelta(days=args.last)).date()

    tags = args.tags.split(",") if args.tags is not None else None

    # building a cache from existing IOCs
    cache = set()
    if args.output != "/dev/stdout" and not args.overwrite:
        if os.path.isfile(args.output):
            info(f"building cache from existing file: {args.output}")
            with open(args.output, "r", encoding="utf-8") as fd:
                for line in fd:
                    ioc = json.loads(line)
                    cache.add(ioc["uuid"])

    OPEN_MODE = "w" if args.overwrite else "a"
    with open(args.output, "a", encoding="utf-8") as fd:
        while True:
            # processing events from a MISP instance
            if misp_config["enable"] is True:
                for ioc in gen_kunai_iocs(
                    misp, misp_config["name"], since, args.all, tags, args.no_to_ids
                ):
                    if ioc["uuid"] not in cache:
                        print(json.dumps(ioc), file=fd)
                        cache.add(ioc["uuid"])

            # processing MISP feeds
            for feed_config in config["misp-feeds"]:
                if feed_config["enable"] is False:
                    continue
                for ioc in kunai_iocs_from_feed(feed_config, since):
                    if ioc["uuid"] not in cache:
                        print(json.dumps(ioc), file=fd)
                        cache.add(ioc["uuid"])

            info(f"number of iocs: {len(cache)}")
            if args.service:
                info(f"waiting {args.wait}s before next run")
                time.sleep(args.wait)
            else:
                break
