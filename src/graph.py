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


class Color:
    def __init__(self, font, bg):
        self.font = font
        self.bg = bg


ZOMBIE_ATTR = "zombie"
DEFAULT_NODE_COLOR = Color("black", "white")
ZOMBIE_COLOR = Color("#FFF000", "#3B5741")
NET_NODE_COLOR = Color("white", "grey")
SUCCESS_COLOR = "green"
FAIL_COLOR = "red"


def color_from_bool(b: bool):
    if b:
        return SUCCESS_COLOR
    return FAIL_COLOR


class Event:
    def __init__(self, event: JqDict):
        self._jq_dict = event

    def __getitem__(self, key):
        return self._jq_dict[key]

    def kind(self):
        return self._jq_dict[".info.event.name"]

    @property
    def task_uuid(self):
        return "guuid={} pid={}".format(
            self._jq_dict[".info.task.guuid"], self._jq_dict[".info.task.pid"]
        )

    @property
    def task_uuid_tgid(self):
        return "guuid={} pid={}".format(
            self._jq_dict[".info.task.guuid"], self._jq_dict[".info.task.tgid"]
        )

    @property
    def parent_task_uuid(self):
        return "guuid={} pid={}".format(
            self._jq_dict[".info.parent_task.guuid"],
            self._jq_dict[".info.parent_task.pid"],
        )


class Task:
    def __init__(self, root: Event):
        self.root = root
        self.nodes = []
        self.clones = []
        self.attributes = set()
        self.capa = set()

    def add(self, node: Event):
        self.nodes.append(node)

    def set_attr(self, *attrs):
        for attr in attrs:
            self.attributes.add(attr)

    def is_zombie(self):
        return ZOMBIE_ATTR in self.attributes

    def label(self):
        try:
            # old kunai logs
            file = self.root[".data.exe.file"]
        except KeyError:
            file = self.root[".data.exe.path"]

        if len(self.attributes) == 0 and len(self.capa) == 0:
            return file

        capas = "|".join(sorted(self.capa))
        if len(self.capa) > 0 and len(self.attributes) == 0:
            return "{{ {} | {} }}".format(file, capas)

        attrs = "|".join(sorted(self.attributes))
        if len(self.capa) > 0 and len(self.attributes) > 0:
            return "{{ {} | {} }} | {{{}}} ".format(file, capas, attrs)

        return "{{ {} }} | {{{}}} ".format(file, attrs)

    def capabilities(self):
        def has_item(f):
            try:
                f.__next__()
                return True
            except StopIteration:
                return False

        if has_item(self.connect):
            self.capa.add("net")
        if has_item(self.send_data):
            self.capa.add("send-data")
            if len(set(map(lambda sd: sd[".data.dst.ip"], self.send_data))) > 50:
                self.capa.add("net-scan")
        if has_item(self.filter_nodes("dns_query")):
            self.capa.add("dns")
        if has_item(self.filter_nodes("write")):
            self.capa.add("write-file")
        if has_item(self.filter_nodes("write_config")):
            self.capa.add("write-config")
        if has_item(self.filter_nodes("bpf_prog_load")):
            self.capa.add("load-bpf-program")
        if has_item(self.filter_nodes("bpf_socket_filter")):
            self.capa.add("bpf-socket-filter")
        if has_item(self.filter_nodes("init_module")):
            self.capa.add("load-kernel-module")
        if has_item(self.filter_nodes("file_unlink")):
            self.capa.add("delete-file")
        if has_item(self.filter_nodes("mprotect_exec")):
            self.capa.add("mprotect-exec")

    def color(self) -> Color:
        if self.is_zombie():
            return ZOMBIE_COLOR
        if len(self.capa):
            s = max(0, 255 - len(self.capa) * 64)
            red = "#FF{i:02X}{i:02X}".format(i=s)
            return Color("black", red)
        return DEFAULT_NODE_COLOR

    def filter_nodes(self, kind) -> filter:
        return filter(lambda n: n.kind() == kind, self.nodes)

    @property
    def connect(self):
        return self.filter_nodes("connect")

    @property
    def send_data(self):
        return self.filter_nodes("send_data")

    def data_sent(self, dst_ip: str, dst_port: int) -> int:
        return sum(
            map(
                lambda n: n[".data.data_size"],
                filter(
                    lambda n: n[".data.dst.ip"] == dst_ip
                    and n[".data.dst.port"] == dst_port,
                    self.send_data,
                ),
            )
        )

    def has_sent_data(self, dst_ip: str, dst_port: int) -> bool:
        try:
            filter(
                lambda n: n[".data.dst.ip"] == dst_ip
                and n[".data.dst.port"] == dst_port,
                self.send_data,
            ).__next__()
            return True
        except StopIteration:
            return False


class KunaiGraph:
    def __init__(self):
        self._tasks = {}
        self._clones = {}
        self._finalized = False

    def _real_parent(self, guuid):
        return self._tasks[guuid].root[".info.parent_task.guuid"]

    def has_task(self, guuid):
        return guuid in self._tasks

    def from_iterator(self, iterator):
        for event in iterator:
            self.update(event)
        self.finalize()

    def update(self, jq_dict: JqDict):
        data = jq_dict["data"]
        info = jq_dict["info"]
        event_type = info["event.name"]
        task = info["task"]
        guuid = task["guuid"]
        parent_task = info["parent_task"]
        pguid = parent_task["guuid"]

        is_zombie = task["zombie"] if task.has_key("zombie") else False

        evt = Event(jq_dict)
        if event_type in ["execve", "execve_script"]:
            if evt.task_uuid not in self._tasks:
                self._tasks[evt.task_uuid] = Task(evt)
            else:
                # print(len(self._tasks[evt.task_uuid].nodes))
                self._tasks[evt.task_uuid].root = evt

        elif event_type == "clone":
            self._tasks[evt.task_uuid] = Task(evt)

        # this check should work with logs with and without zombie flag
        elif is_zombie or (
            self.has_task(evt.task_uuid) and self._real_parent(evt.task_uuid) != pguid
        ):
            self._tasks[evt.task_uuid].set_attr(ZOMBIE_ATTR)

        # adding events to tasks
        if event_type not in ["execve", "execve_script", "clone"]:
            if evt.task_uuid in self._tasks:
                self._tasks[evt.task_uuid].add(evt)

    def finalize(self):
        if self._finalized:
            return

        for t in self._tasks.values():
            t.capabilities()

        self._finalized = True

    def to_svg_bytes(self) -> bytes:
        self.finalize()

        tmp_dir = tempfile.mkdtemp(suffix="kunai-graph")
        tmp_out = os.path.join(tmp_dir, "graph")

        dot = graphviz.Digraph(
            comment="Process Activity Graph",
            node_attr={
                "shape": "record",
                "style": "rounded,filled",
                "fontname": "Arial",
                "fillcolor": "white",
            },
            edge_attr={"fontname": "Arial", "labelangle": "-180.0"},
        )

        for task in self._tasks.values():
            task_node = task.root
            node_color = task.color()
            task_guid = task_node[".info.task.guuid"]

            if task_node.kind() in ["execve", "execve_script"]:
                label = (
                    self._tasks[task_node.parent_task_uuid].label()
                    if task_node.parent_task_uuid in self._tasks
                    else task_node[".data.parent_exe"]
                )

                label, color = (task_node[".data.parent_exe"], DEFAULT_NODE_COLOR)
                if task_node.parent_task_uuid in self._tasks:
                    p = self._tasks[task_node.parent_task_uuid]
                    label, color = p.label(), p.color()

                dot.node(
                    task_node.parent_task_uuid,
                    label,
                    fillcolor=color.bg,
                    fontcolor=color.font,
                )

            dot.node(
                task_node.task_uuid,
                task.label(),
                fillcolor=node_color.bg,
                fontcolor=node_color.font,
            )

            label, style = (
                ("clone", "dotted")
                if task_node.kind() == "clone"
                else ("execve", "solid")
            )

            if task_node.kind() == "clone":
                clone_flags = int(task_node[".data.flags"], 16)
                # we handle specific case where CLONE_PARENT | CLONE_THREAD is used
                # https://elixir.bootlin.com/linux/v6.9.5/source/kernel/fork.c#L2519
                # in this case parent is not current task at clone time
                if check_flag(clone_flags, 0x00010000) or check_flag(
                    clone_flags, 0x00008000
                ):
                    dot.edge(
                        task_node.task_uuid_tgid,
                        task_node.task_uuid,
                        label=label,
                        style=style,
                    )
                else:
                    dot.edge(
                        task_node.parent_task_uuid,
                        task_node.task_uuid,
                        label=label,
                        style=style,
                    )
            else:
                dot.edge(
                    task_node.parent_task_uuid,
                    task_node.task_uuid,
                    label=label,
                    style=style,
                )

            marked_con = set()
            for con in task.connect:
                dst_ip = con[".data.dst.ip"]
                host = con[".data.dst.hostname"]
                dst_port = con[".data.dst.port"]

                dst_node = (
                    f"{host}:{dst_port}" if host != "?" else f"{dst_ip}:{dst_port}"
                )

                if dst_node in marked_con:
                    continue

                node_name = "{}".format(uuid.uuid5(uuid.NAMESPACE_OID, dst_node))
                dot.node(
                    node_name,
                    label=dst_node,
                    fillcolor=NET_NODE_COLOR.bg,
                    fontcolor=NET_NODE_COLOR.font,
                )

                label = "con"
                color = color_from_bool(con[".data.connected"])
                if task.has_sent_data(dst_ip, dst_port):
                    byte_sent = task.data_sent(dst_ip, dst_port)
                    label = f"send: {byte_sent}B"
                    color = "blue"

                dot.edge(
                    task_node.task_uuid,
                    node_name,
                    label=label,
                    style="dashed",
                    color=color,
                    fontcolor=color,
                )
                marked_con.add(dst_node)

            unique_ips = set(map(lambda sd: sd[".data.dst.ip"], task.send_data))

            if len(unique_ips) > 30:
                name = f"{task_node.task_uuid}|send-data"
                # box shape is needed there to do new line
                dot.node(
                    name,
                    f"send-data to {len(unique_ips)} IP addresses\nreview logs to see them all",
                    fillcolor=NET_NODE_COLOR.bg,
                    fontcolor=NET_NODE_COLOR.font,
                    shape="box",
                )
                dot.edge(
                    task_node.task_uuid,
                    name,
                    label="send",
                    style="dashed",
                    color="blue",
                    fontcolor="blue",
                )
            else:
                for send in task.send_data:
                    dst_ip = send[".data.dst.ip"]
                    dst_port = send[".data.dst.port"]
                    host = send[".data.dst.hostname"]

                    dst_node = (
                        f"{host}:{dst_port}" if host != "?" else f"{dst_ip}:{dst_port}"
                    )

                    if dst_node in marked_con:
                        continue

                    node_name = "{}".format(uuid.uuid5(uuid.NAMESPACE_OID, dst_node))
                    dot.node(
                        node_name,
                        label=dst_node,
                        fillcolor=NET_NODE_COLOR.bg,
                        fontcolor=NET_NODE_COLOR.font,
                    )

                    byte_sent = task.data_sent(dst_ip, dst_port)
                    label = f"send: {byte_sent}B"

                    dot.edge(
                        task_node.task_uuid,
                        node_name,
                        label=label,
                        style="dashed",
                        color="blue",
                        fontcolor="blue",
                    )
                    marked_con.add(dst_node)

        dot.render(tmp_out, format="svg")

        out = bytes()
        with open(f"{tmp_out}.svg", "rb") as fd:
            out = fd.read()

        os.remove(f"{tmp_out}")
        os.remove(f"{tmp_out}.svg")
        os.rmdir(tmp_dir)

        return out

    def to_svg(self, filename: str):
        with open(filename, "wb") as fd:
            fd.write(self.to_svg_bytes())


def check_flag(value, flag) -> bool:
    return value & flag == flag


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
