#!/usr/bin/env python3

import argparse
import json
import sys
import logging
import re
import hashlib

logger = logging.Logger(__file__)

class Query(object):

    def __init__(self, recurse=True):
        self.guids = set()
        self.hashes = set()
        self.regexes = {}
        # track child tasks
        self.recurse = recurse
        self.filter_in = set()
        self.filter_out = set()
    
    def add_guids(self, guids):
        for guid in guids:
            # guid normalization
            guid = guid.strip("{}")
            if len(guid) != 36:
                logger.error("Bad guid length for: {0}".format(guid))
                continue
            self.guids.add(guid)
    
    def add_hashes(self, hashes):
        for hash in hashes:
            self.hashes.add(hash)

    def add_regexp(self, regexes):
        for regex in regexes:
            self.regexes[regex] = re.compile(regex, re.I)
    
    def add_filters(self, filters):
        for f in filters:
            f = int(f)
            if f > 0:
                self.filter_in.add(f)
            else:
                self.filter_out.add(-f)

    
    def _update(self, event):
        '''
        Update query object from an event
        '''
        if self.recurse:
            if "info" in event:
                if "task" in event["info"]:
                    guid = event["info"]["task"]["guuid"]
                    self.add_guids([guid])

    def _match_regex(self, s):
        s = str(s)
        for k, r in self.regexes.items():
            if r.search(s):
                return True
        return False
    
    def _filtered_out(self, eventid):
        if len(self.filter_in):
            if eventid not in self.filter_in:
                return True
        if len(self.filter_out):
            if eventid in self.filter_out:
                return True
        return False

    def _filtered_in(self, eventid):
        if len(self.filter_in):
            if eventid in self.filter_in:
                return True
        if len(self.filter_out):
            if eventid not in self.filter_out:
                return True
        return False

    def _recursive_walk(self, dictionary):
        for key, value in dictionary.items():
            if isinstance(value, dict):
                for k,v in self._recursive_walk(value):
                    yield k,v
            yield key,value
    
    def match(self, event):
        if "info" in event and "data" in event:

            eventdata = event["data"]
            task_info = event["info"]["task"]
            ptask_info = event["info"]["parent_task"]

            # check for event id
            if "event" in event["info"]:
                if "id" in event["info"]["event"]:
                    eid = int(event["info"]["event"]["id"])
                    if self._filtered_out(eid):
                        return False
                    if self._filtered_in(eid):
                        return True

            # check for event data
            if "data" in event:

                # if create process
                if task_info["guuid"] in self.guids or ptask_info["guuid"] in self.guids:
                    self._update(event)
                    return True

                for k, v in self._recursive_walk(event):
                    # check for Hashes
                    if k in ["md5", "sha1", "sha256", "sha512"]:
                        if v in self.hashes:
                            self._update(event)
                            return True

                    if self._match_regex(v):
                        self._update(event)
                        return True

        return False

def gen_events(fd):
    for line in fd.readlines():
        yield json.loads(line)

def sha256_file(file_path):
    sha256 = hashlib.sha256()
    
    with open(file_path, 'rb') as file:
        for chunk in iter(lambda: file.read(4096), b''):
            sha256.update(chunk)
    
    return sha256.hexdigest()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Helper script to easily search in Kunai logs")
    parser.add_argument("--no-recurse", action="store_false", help="Does a recursive search (goes to child processes as well)")
    parser.add_argument("-g", "--guids", type=str, help="Search by task_uuid (comma split)")
    parser.add_argument("-P", "--regexes", type=str, help="Search by regexp (comma split)")
    parser.add_argument("-c", "--hashes", type=str, help="Search by hash (comma split)")
    parser.add_argument("-F", "--file", type=str, help="Hash file and search by hash")
    parser.add_argument("-f", "--filters", type=str, help="Filters output to display or not (- prefix) some event ids. Example: --filter=-1,-2 would show all events except event with id 1 or 2")
    parser.add_argument("kunai_json_input", help="Input file in json line format or stdin with -")

    args = parser.parse_args()

    query = Query(args.no_recurse)

    if args.kunai_json_input == "-":
        eg = gen_events(sys.stdin)
    else:
        eg = gen_events(open(args.kunai_json_input, "r"))

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
            print(json.dumps(event))
