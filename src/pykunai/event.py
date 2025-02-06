import re
import json
from typing import List, Generator, Tuple


class JqDict:
    def __init__(self, d: dict) -> None:
        self._dict = d

    def has_key(self, key: str) -> bool:
        return key in self._dict

    def __getitem__(self, key: str) -> object:
        def __get_rec(d: dict, path: list) -> JqDict:
            if len(path) == 1:
                k = path.pop(0)
                o = d[k]
                if isinstance(o, dict):
                    return JqDict(o)
                return o
            elif len(path) > 0:
                k = path.pop(0)
                return __get_rec(d[k], path)

        return __get_rec(self._dict, key.strip(".").split("."))

    def __contains__(self, key: str) -> bool:
        return key in self._dict

    def __str__(self) -> str:
        return self._dict.__str__()

    def __eq__(self, other: object) -> bool:
        return self._dict == other._dict

    def __hash__(self) -> int:
        return hash(json.dumps(self._dict))

    def json(self) -> str:
        return json.dumps(self._dict)


class Event:
    def __init__(self, event: JqDict) -> None:
        self.event = event

    def __getitem__(self, key: str) -> object:
        return self.event[key]

    def __contains__(self, key: str) -> bool:
        try:
            return self.event[key] is not None
        except KeyError:
            return False

    @property
    def type_str(self) -> str:
        return self.event[".info.event.name"]

    @property
    def data(self) -> JqDict:
        return self.event[".data"]

    @property
    def info(self) -> JqDict:
        return self.event[".info"]

    @property
    def attack(self) -> set:
        if ".detection.attack" in self:
            return set(self[".detection.attack"])
        return set()

    @property
    def utc_time_str(self) -> str:
        return self[".info.utc_time"]

    @property
    def task_guuid(self) -> str:
        return self[".info.task.guuid"]

    @property
    def parent_task_guuid(self) -> str:
        return self[".info.parent_task.guuid"]

    def json(self) -> str:
        return self.event.json()

    def items(self):  # noqa: ANN201
        return self.event._dict.items()

    def jq_dict(self) -> JqDict:
        return self.event


class GuidFormat(Exception):
    def __init__(self) -> None:
        super(Exception, self)


class Query(object):
    def __init__(self, recurse: bool = True) -> None:
        self.guids = set()
        self.hashes = set()
        self.regexes = {}
        # track child tasks
        self.recurse = recurse
        self.filter_in = set()
        self.filter_out = set()

    def is_empty(self) -> bool:
        return len(self.hashes) == 0 and len(self.guids) == 0 and len(self.regexes) == 0

    def add_guids(self, guids: List[str]) -> None:
        for guid in guids:
            # guid normalization
            guid = guid.strip("{}")
            if len(guid) != 36:
                raise GuidFormat()
            self.guids.add(guid)

    def add_hashes(self, hashes: List[str]) -> None:
        for h in hashes:
            self.hashes.add(h)

    def add_regexp(self, regexes: List[str]) -> None:
        for regex in regexes:
            self.regexes[regex] = re.compile(regex, re.I)

    def add_filters(self, filters: List[int]) -> None:
        for f in filters:
            f = int(f)
            if f > 0:
                self.filter_in.add(f)
            else:
                self.filter_out.add(-f)

    def _update(self, event: Event) -> None:
        """
        Update query object from an event
        """
        if self.recurse:
            if "info" in event:
                if "task" in event["info"]:
                    guid = event["info.task.guuid"]
                    self.add_guids([guid])

    def _match_regex(self, s: object) -> bool:
        s = str(s)
        for k, r in self.regexes.items():
            if r.search(s):
                return True
        return False

    def _filtered_out(self, eventid: int) -> bool:
        if len(self.filter_in) > 0:
            if eventid not in self.filter_in:
                return True
        if len(self.filter_out) > 0:
            if eventid in self.filter_out:
                return True
        return False

    def _filtered_in(self, eventid: int) -> bool:
        if len(self.filter_in) > 0:
            if eventid in self.filter_in:
                return True
        if len(self.filter_out) > 0:
            if eventid not in self.filter_out:
                return True
        return False

    def _recursive_walk(
        self, event: Event
    ) -> Generator[Tuple[str, object], None, None]:
        for key, value in event.items():
            if isinstance(value, dict):
                for k, v in self._recursive_walk(value):
                    yield k, v
            yield key, value

    def match(self, event: Event) -> bool:
        if "info" in event and "data" in event:
            task_info = event[".info.task"]
            ptask_info = event["info.parent_task"]

            # check for event id
            if "event" in event["info"]:
                if "id" in event["info.event"]:
                    eid = int(event["info.event.id"])
                    if self._filtered_out(eid):
                        return False
                    if self._filtered_in(eid):
                        return True

            # check for event data
            if "data" in event:
                # if create process
                if (
                    task_info["guuid"] in self.guids
                    or ptask_info["guuid"] in self.guids
                ):
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
