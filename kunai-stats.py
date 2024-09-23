#!/usr/bin/env python

import argparse
import json
import os
import sys
from datetime import datetime

def format_bytes(size):
    # Define the units and their corresponding sizes
    units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB']
    
    # Loop through each unit
    for unit in units:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

    return f"{size:.2f} YB"

def lines(fd):
    for line in map(lambda l: l.strip(), fd):
        yield line

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Makes statistics about kunai logs")
    parser.add_argument("-r", "--refresh", default=300, type=int, help="Refresh rate in numbers of events")
    parser.add_argument("kunai_json_input", help="Input file in json line format or stdin with -")

    args = parser.parse_args()

    if args.kunai_json_input == "-":
        lg = lines(sys.stdin)
    else:
        lg = lines(open(args.kunai_json_input, "r"))
    
    stats = {}
    count, size = 0, 0
    first, last = 0, 0
    for line in lg:
        event = json.loads(line)
        timestamp=datetime.fromisoformat(event["info"]["utc_time"])
        eid = event["info"]["event"]["id"]
        ename = event["info"]["event"]["name"]
        key = (eid, ename)
        if key not in stats:
            stats[key] = 0
        stats[key] += 1
        count += 1
        size += len(line)

        if first == 0:
            first = timestamp
        last = timestamp

        if count != 0 and count % args.refresh == 0:
            os.system("clear")
            delta = last - first

            if delta.total_seconds() == 0:
                continue

            for k in sorted(stats, key=lambda k: k[0]):
                c = stats[k]
                eps = c / delta.total_seconds()
                print(f"{k[1]}:".ljust(20), end=' ')
                print(f"{c} ->".rjust(10), end=' ')
                print(f"{eps:.2f} e/s".rjust(12))
            tot_eps = count / delta.total_seconds()
            tot_bps = size / delta.total_seconds()
            print()
            print("Totals")
            print("Events:".ljust(20), end=' ')
            print(f"{count} ->".rjust(10), end=' ')
            print(f"{tot_eps:.2f} e/s".rjust(12))
            # size in bytes
            print("Bytes:".ljust(20), end=' ')
            print(f"{format_bytes(size)} ->".rjust(10), end=' ')
            print(f"{format_bytes(tot_bps)}/s".rjust(12))
            # time
            print("Sample Duration:".ljust(20), end=' ')
            print(f"{delta}".rjust(10))

