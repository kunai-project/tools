Library and tools for [Kunai](https://github.com/kunai-project/kunai).

# Installing tools

```bash
uv tool install pykunai
```

# Upgrade tools

```bash
uv tool upgrade pykunai
```

# Tools

## misp-to-kunai

Pulls IoCs from a [MISP](https://www.misp-project.org/) instance or [MISP feeds](https://www.misp-project.org/feeds/#default-feeds-available-in-misp)
and formats it to be ingested by kunai.

**Configuration**: [see configuration file](./src/pykunai/tools/config/config.example.toml)

```
usage: misp-to-kunai [-h] [-c CONFIG] [-s] [-l LAST] [-o OUTPUT] [--overwrite] [--all] [--tags TAGS] [--wait WAIT]
                     [--service]

Tool pulling IoCs from a MISP instance and converting them to be loadable in Kunai

options:
  -h, --help           show this help message and exit
  -c, --config CONFIG  Configuration file. Default: /home/kunai-user/kunai-
                       project/tools/src/pykunai/tools/config.toml
  -s, --silent         Silent HTTPS warnings
  -l, --last LAST      Process events updated the last days
  -o, --output OUTPUT  Output file
  --overwrite          Overwrite output file (default is to append)
  --all                Process all events, published and unpublished. By default only published events are
                       processed.
  --tags TAGS          Comma separated list of (event tags) to pull iocs for
  --wait WAIT          Wait time in seconds between to runs in service mode
  --service            Run in service mode (i.e endless loop)
```


## kunai-to-misp

Uses Kunai logs to create a [MISP](https://www.misp-project.org/) event to share IoCs with the community.

**Configuration**: [see configuration file](./src/pykunai/tools/config/config.example.toml)

One use case example is:
1. analyze a malware sample with [Kunai Sandbox](https://github.com/kunai-project/sandbox)
2. use `kunai-to-misp` on the kunai logs collected
3. **OPTIONAL**: review attributes' IDS flag to **maximize detections** and **lower false positives**
4. use `misp-to-kunai` to benefit from the result of the analysis in all of the kunai endpoints

```
usage: kunai-to-misp [-h] [-c CONFIG] [--no-recurse] [-s] [-H HASHES] [-F FILE] [-G GUUID] KUNAI_JSON_INPUT

Push Kunai analysis to MISP

positional arguments:
  KUNAI_JSON_INPUT     Input file in json line format or stdin with -

options:
  -h, --help           show this help message and exit
  -c, --config CONFIG  Configuration file. Default: /home/kunai-user/kunai-
                       project/tools/src/pykunai/tools/config.toml
  --no-recurse         Does a recursive search (goes to child processes as well)
  -s, --silent         Silent HTTPS warnings
  -H, --hashes HASHES  Search by hash (comma split)
  -F, --file FILE      Hash file and search by hash
  -G, --guuid GUUID    Search by task guuid (comma split)
```

## kunai-search

Easily search / filter kunai logs for manual inspection

```
usage: kunai-search [-h] [--no-recurse] [-g GUIDS] [-P REGEXES] [-c HASHES] [-F FILE] [-f FILTERS] kunai_json_input

Helper script to easily search in Kunai logs

positional arguments:
  kunai_json_input      Input file in json line format or stdin with -

options:
  -h, --help            show this help message and exit
  --no-recurse          Does a recursive search (goes to child processes as well)
  -g, --guids GUIDS     Search by task_uuid (comma split)
  -P, --regexes REGEXES
                        Search by regexp (comma split)
  -c, --hashes HASHES   Search by hash (comma split)
  -F, --file FILE       Hash file and search by hash
  -f, --filters FILTERS
                        Filters output to display or not (- prefix) some event ids. Example: --filter=-1,-2 would
                        show all events except event with id 1 or 2
```

## kunai-graph

Build a visual representation (in SVG) of Kunai logs.

```
usage: kunai-graph [-h] -o OUTPUT KUNAI_LOGS

Transform kunai logs to mermaid graph

positional arguments:
  KUNAI_LOGS           Kunai logs. Default: stdin

options:
  -h, --help           show this help message and exit
  -o, --output OUTPUT  Ouptut file
```

## kunai-iocgen

Generate a Kunai IoC from command line. This is particularly useful
to automate IoC generation.

```
usage: kunai-iocgen [-h] source value severity

Help creating iocs from batch

positional arguments:
  source      IoC source
  value       IoC value
  severity    IoC value

options:
  -h, --help  show this help message and exit
```

# Funding

The NGSOTI project is dedicated to training the next generation of Security Operation Center (SOC) operators, focusing on the human aspect of cybersecurity.
It underscores the significance of providing SOC operators with the necessary skills and open-source tools to address challenges such as detection engineering, 
incident response, and threat intelligence analysis. Involving key partners such as CIRCL, Restena, Tenzir, and the University of Luxembourg, the project aims
to establish a real operational infrastructure for practical training. This initiative integrates academic curricula with industry insights, 
offering hands-on experience in cyber ranges.

NGSOTI is co-funded under Digital Europe Programme (DEP) via the ECCC (European cybersecurity competence network and competence centre).
