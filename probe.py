#!/usr/bin/env python3
"""Probe live PX4/Gazebo/MAVLink/video connections in this dev environment."""

from __future__ import annotations

import argparse
import configparser
import re
import shutil
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


DEFAULT_ROUTER_CONFIG = ".devcontainer/docker-builder/mavlink_router_conf/mavlink_router_conf.conf"

KNOWN_PORTS = {
    4560: "Gazebo <-> PX4 simulator TCP",
    14505: "Trillium emulator output UDP",
    14530: "Gazebo camera manager MAVLink UDP",
    14550: "GCS/QGroundControl UDP target",
    14560: "Gazebo MAVLink UDP",
    14580: "PX4 offboard MAVLink local UDP",
    18570: "PX4 GCS MAVLink local UDP",
    14280: "PX4 onboard payload local UDP",
    14030: "PX4 onboard payload remote UDP",
    13030: "PX4 onboard gimbal local UDP",
    13280: "PX4 onboard gimbal remote UDP",
    24540: "Trillium emulator input UDP",
    5600: "Gazebo camera RTP/H264 UDP video",
    5002: "Ignite UDP video",
}


@dataclass(frozen=True)
class Endpoint:
    section: str
    name: str
    kind: str
    mode: str
    address: str
    port: int | None
    protocol: str


@dataclass(frozen=True)
class SocketRow:
    proto: str
    local: str
    remote: str
    state: str
    owner: str
    description: str


PACKET_RE = re.compile(
    r"^\S+\s+(?:\S+\s+(?:In|Out)\s+)?IP6?\s+"
    r"(?P<src>\S+)\s+>\s+(?P<dst>\S+?):\s+"
    r"(?P<proto>UDP|TCP).*"
)


def run_command(command: list[str], input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, input=input_text, check=False, capture_output=True, text=True)


def parse_endpoint_address(endpoint: str) -> tuple[str, int | None]:
    if endpoint in {"*", "0.0.0.0:*", ":::*"}:
        return endpoint, None

    host, separator, port_text = endpoint.rpartition(":")
    if not separator:
        host, separator, port_text = endpoint.rpartition(".")
        if not separator:
            return endpoint, None

    try:
        return host.strip("[]"), int(port_text)
    except ValueError:
        return endpoint, None


def is_wildcard_address(address: str) -> bool:
    return address.strip().strip("[]") in {"0.0.0.0", "::", ""}


def is_local_address(address: str) -> bool:
    normalized = address.strip().strip("[]").lower()
    return normalized in {"127.0.0.1", "localhost", "::1"}


def parse_router_config(path: Path) -> list[Endpoint]:
    parser = configparser.ConfigParser(strict=False)
    parser.optionxform = str.lower
    parser.read(path)

    endpoints: list[Endpoint] = []

    if parser.has_section("General") and parser.has_option("General", "tcpserverport"):
        endpoints.append(
            Endpoint(
                section="General",
                name="TcpServer",
                kind="TcpServer",
                mode="server",
                address="0.0.0.0",
                port=parser.getint("General", "tcpserverport"),
                protocol="tcp",
            )
        )

    for section in parser.sections():
        section_type, _, endpoint_name = section.partition(" ")
        section_type_lower = section_type.lower()
        if section_type_lower not in {"udpendpoint", "tcpendpoint"}:
            continue

        endpoint = parser[section]
        protocol = "udp" if section_type_lower == "udpendpoint" else "tcp"
        default_mode = "normal" if protocol == "udp" else "client"
        port = endpoint.getint("port", fallback=None)
        endpoints.append(
            Endpoint(
                section=section,
                name=endpoint_name or section,
                kind=section_type,
                mode=endpoint.get("mode", fallback=default_mode).lower(),
                address=endpoint.get("address", fallback=""),
                port=port,
                protocol=protocol,
            )
        )

    return endpoints


def endpoint_label_by_port(endpoints: list[Endpoint]) -> dict[int, str]:
    labels = dict(KNOWN_PORTS)
    for endpoint in endpoints:
        if endpoint.port is not None:
            labels[endpoint.port] = f"mavlink-router {endpoint.name} {endpoint.protocol.upper()} ({endpoint.mode})"
    return labels


def label_for_port(port: int | None, labels: dict[int, str]) -> str:
    if port is None:
        return "unlabeled destination"
    return labels.get(port, "unlabeled destination")


def describe_socket(local: str, remote: str, labels: dict[int, str]) -> str:
    _, local_port = parse_endpoint_address(local)
    _, remote_port = parse_endpoint_address(remote)
    descriptions = []

    if local_port in labels:
        descriptions.append(f"local {local_port}: {labels[local_port]}")

    if remote_port in labels and remote_port != local_port:
        descriptions.append(f"remote {remote_port}: {labels[remote_port]}")

    return "; ".join(descriptions)


def endpoint_matches_port(endpoint: str, ports: set[int]) -> bool:
    _, port = parse_endpoint_address(endpoint)
    return port in ports


def read_netstat(labels: dict[int, str], ports: set[int] | None = None) -> list[SocketRow]:
    if not shutil.which("netstat"):
        raise RuntimeError("netstat is not available on PATH")

    output = run_command(["netstat", "-tunap"])
    rows: list[SocketRow] = []

    for line in output.stdout.splitlines():
        parts = line.split()
        if len(parts) < 6 or not parts[0].startswith(("tcp", "udp")):
            continue

        proto = parts[0]
        local = parts[3]
        remote = parts[4]

        if ports is not None and not endpoint_matches_port(local, ports) and not endpoint_matches_port(remote, ports):
            continue

        if proto.startswith("tcp"):
            state = parts[5]
            owner = parts[6] if len(parts) > 6 else "-"
        else:
            state = "-"
            owner = parts[5] if len(parts) > 5 else "-"

        rows.append(SocketRow(proto, local, remote, state, owner, describe_socket(local, remote, labels)))

    return rows


def tcpdump_port_filter(ports: set[int], protocol: str | None = None) -> str:
    terms = []
    protocols = [protocol] if protocol else ["tcp", "udp"]
    for port in sorted(ports):
        for proto in protocols:
            terms.append(f"{proto} port {port}")
    return " or ".join(terms)


def tcpdump_source_filter(ports: set[int]) -> str:
    terms = []
    for port in sorted(ports):
        terms.append(f"tcp src port {port}")
        terms.append(f"udp src port {port}")
    return " or ".join(terms)


def parse_packet_line(line: str) -> tuple[str, int | None, str, int | None, str, int] | None:
    match = PACKET_RE.match(line)
    if not match:
        return None

    src_host, src_port = parse_endpoint_address(match.group("src"))
    dst_host, dst_port = parse_endpoint_address(match.group("dst"))
    length_match = re.search(r"length\s+(\d+)", line)
    length = int(length_match.group(1)) if length_match else 0
    return src_host, src_port, dst_host, dst_port, match.group("proto"), length


def run_tcpdump(interface: str, seconds: int, filter_expression: str) -> subprocess.CompletedProcess[str] | None:
    if seconds <= 0:
        return None

    if not shutil.which("tcpdump"):
        print("tcpdump is not available; skipping packet sniff")
        return None

    return run_command(
        ["timeout", str(seconds), "tcpdump", "-i", interface, "-nn", "-tt", "-q", filter_expression]
    )


def summarize_packet_output(output: str, labels: dict[int, str]) -> None:
    conversations = defaultdict(lambda: {"packets": 0, "bytes": 0})
    raw_lines = [line for line in output.splitlines() if " IP " in line or " IP6 " in line]

    for line in raw_lines:
        packet = parse_packet_line(line)
        if packet is None:
            continue

        src_host, src_port, dst_host, dst_port, protocol, length = packet
        key = (protocol, src_host, src_port, dst_host, dst_port)
        conversations[key]["packets"] += 1
        conversations[key]["bytes"] += length

    if not conversations:
        print("No matching packets observed in the sample window.")
        return

    for (protocol, src_host, src_port, dst_host, dst_port), stats in sorted(
        conversations.items(), key=lambda item: item[1]["packets"], reverse=True
    ):
        print(
            f"{protocol:3} {src_host}:{src_port} -> {dst_host}:{dst_port} "
            f"packets={stats['packets']} bytes={stats['bytes']} ({label_for_port(dst_port, labels)})"
        )


def print_tcpdump_result(result: subprocess.CompletedProcess[str] | None, labels: dict[int, str]) -> None:
    if result is None:
        return

    stderr = result.stderr.lower()
    if "permission denied" in stderr or "operation not permitted" in stderr:
        print("tcpdump needs capture permissions; try running this script with sudo")
        return

    summarize_packet_output(result.stdout, labels)


def sniff_packets(interface: str, ports: set[int], seconds: int, labels: dict[int, str]) -> None:
    if seconds <= 0:
        return

    print(f"\nPacket sample for {seconds}s on {interface}:")
    print_tcpdump_result(run_tcpdump(interface, seconds, tcpdump_port_filter(ports)), labels)


def print_socket_rows(rows: list[SocketRow]) -> None:
    if not rows:
        print("No matching sockets found.")
        return

    widths = {
        "proto": max(5, *(len(row.proto) for row in rows)),
        "local": max(5, *(len(row.local) for row in rows)),
        "remote": max(6, *(len(row.remote) for row in rows)),
        "state": max(5, *(len(row.state) for row in rows)),
        "owner": max(5, *(len(row.owner) for row in rows)),
    }

    print(
        f"{'PROTO':<{widths['proto']}}  "
        f"{'LOCAL':<{widths['local']}}  "
        f"{'REMOTE':<{widths['remote']}}  "
        f"{'STATE':<{widths['state']}}  "
        f"{'OWNER':<{widths['owner']}}  DESCRIPTION"
    )

    for row in rows:
        print(
            f"{row.proto:<{widths['proto']}}  "
            f"{row.local:<{widths['local']}}  "
            f"{row.remote:<{widths['remote']}}  "
            f"{row.state:<{widths['state']}}  "
            f"{row.owner:<{widths['owner']}}  {row.description}"
        )


def print_endpoint_rows(endpoints: list[Endpoint]) -> None:
    if not endpoints:
        print("No router endpoints found.")
        return

    widths = {
        "name": max(4, *(len(endpoint.name) for endpoint in endpoints)),
        "kind": max(4, *(len(endpoint.kind) for endpoint in endpoints)),
        "mode": max(4, *(len(endpoint.mode) for endpoint in endpoints)),
        "address": max(7, *(len(endpoint.address or "-") for endpoint in endpoints)),
        "port": max(4, *(len(str(endpoint.port or "-")) for endpoint in endpoints)),
        "protocol": max(8, *(len(endpoint.protocol) for endpoint in endpoints)),
    }

    print(
        f"{'NAME':<{widths['name']}}  "
        f"{'KIND':<{widths['kind']}}  "
        f"{'MODE':<{widths['mode']}}  "
        f"{'ADDRESS':<{widths['address']}}  "
        f"{'PORT':<{widths['port']}}  "
        f"{'PROTOCOL':<{widths['protocol']}}"
    )
    for endpoint in endpoints:
        print(
            f"{endpoint.name:<{widths['name']}}  "
            f"{endpoint.kind:<{widths['kind']}}  "
            f"{endpoint.mode:<{widths['mode']}}  "
            f"{(endpoint.address or '-'):<{widths['address']}}  "
            f"{str(endpoint.port or '-'):<{widths['port']}}  "
            f"{endpoint.protocol:<{widths['protocol']}}"
        )


def local_interface_ips() -> list[str]:
    result = run_command(["hostname", "-I"])
    ips = result.stdout.split()
    return ips or ["127.0.0.1"]


def ping_address(address: str) -> None:
    if is_wildcard_address(address):
        print(f"Ping: skipped {address}; wildcard address, not a host.")
        print(f"Local interface IPs: {', '.join(local_interface_ips())}")
        return

    if not shutil.which("ping"):
        print("Ping: ping command not available.")
        return

    target = "127.0.0.1" if is_local_address(address) else address.strip().strip("[]")
    result = run_command(["ping", "-c", "1", "-W", "1", target])
    status = "ok" if result.returncode == 0 else "failed"
    print(f"Ping {target}: {status}")


def find_endpoints(endpoints: list[Endpoint], names: list[str], ports: set[int]) -> list[Endpoint]:
    name_set = {name.lower() for name in names}
    matches = []
    for endpoint in endpoints:
        if endpoint.name.lower() in name_set or (endpoint.port is not None and endpoint.port in ports):
            matches.append(endpoint)
    return matches


def probe_router_endpoint(endpoint: Endpoint, interface: str, seconds: int, labels: dict[int, str]) -> None:
    print(f"\n=== Router endpoint: {endpoint.name} ===")
    print(f"Type: {endpoint.kind}")
    print(f"Mode: {endpoint.mode}")
    print(f"Address: {endpoint.address or '-'}")
    print(f"Port: {endpoint.port or '-'}")
    print(f"Protocol: {endpoint.protocol}")

    if endpoint.address:
        ping_address(endpoint.address)

    if endpoint.port is None:
        print("No port configured; skipping socket and packet checks.")
        return

    print("\nSockets using endpoint port:")
    print_socket_rows(read_netstat(labels, {endpoint.port}))

    if seconds <= 0:
        print("\nAdd --sniff SECONDS to check whether packets are flowing through this endpoint.")
        return

    print(f"\nTraffic sample for {endpoint.protocol} port {endpoint.port} ({seconds}s on {interface}):")
    print_tcpdump_result(run_tcpdump(interface, seconds, tcpdump_port_filter({endpoint.port}, endpoint.protocol)), labels)


def probe_owner_outgoing(owner_filter: str, interface: str, seconds: int, labels: dict[int, str]) -> None:
    rows = [row for row in read_netstat(labels) if owner_filter in row.owner]
    if not rows:
        print(f"No sockets owned by {owner_filter!r} found.")
        return

    print(f"\n=== Sockets owned by {owner_filter} ===")
    print_socket_rows(rows)

    source_ports = set()
    for row in rows:
        _, port = parse_endpoint_address(row.local)
        if port is not None:
            source_ports.add(port)

    if seconds <= 0:
        print("\nAdd --sniff SECONDS to sample outgoing packets from those source ports.")
        return

    print(f"\n=== Outgoing packet sample from {owner_filter} ({seconds}s on {interface}) ===")
    print_tcpdump_result(run_tcpdump(interface, seconds, tcpdump_source_filter(source_ports)), labels)


def parse_ports(raw_ports: str) -> set[int]:
    ports = set()
    for value in raw_ports.split(","):
        value = value.strip()
        if value:
            ports.add(int(value))
    return ports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--router-config", default=DEFAULT_ROUTER_CONFIG, help="Path to mavlink-router config.")
    parser.add_argument("--list-router-endpoints", action="store_true", help="List parsed mavlink-router endpoints.")
    parser.add_argument("--probe-endpoint", action="append", default=[], help="Probe router endpoint by name.")
    parser.add_argument("--find-port", action="append", type=int, default=[], help="Find/probe router endpoint by port.")
    parser.add_argument(
        "--ports",
        default="",
        help="Comma-separated ports for generic socket probing. Defaults to known and parsed router ports.",
    )
    parser.add_argument("--interval", type=float, default=1.0, help="Seconds between socket snapshots.")
    parser.add_argument("--count", type=int, default=1, help="Number of snapshots. Use 0 to run until Ctrl+C.")
    parser.add_argument("--sniff", type=int, default=0, help="Also sample packets for this many seconds per snapshot.")
    parser.add_argument("--interface", default="any", help="tcpdump interface for --sniff, usually any or lo.")
    parser.add_argument("--owner-outgoing", help="Summarize outgoing packets from sockets owned by this process name.")
    args = parser.parse_args()

    router_config = Path(args.router_config)
    endpoints = parse_router_config(router_config) if router_config.exists() else []
    labels = endpoint_label_by_port(endpoints)

    if args.list_router_endpoints:
        print_endpoint_rows(endpoints)
        return 0

    endpoint_matches = find_endpoints(endpoints, args.probe_endpoint, set(args.find_port))
    if args.probe_endpoint or args.find_port:
        if not endpoint_matches:
            print("No matching router endpoints found.")
            return 1
        for endpoint in endpoint_matches:
            probe_router_endpoint(endpoint, args.interface, args.sniff, labels)
        return 0

    if args.owner_outgoing:
        probe_owner_outgoing(args.owner_outgoing, args.interface, args.sniff, labels)
        return 0

    router_ports = {endpoint.port for endpoint in endpoints if endpoint.port is not None}
    ports = parse_ports(args.ports) if args.ports else set(KNOWN_PORTS) | router_ports
    iteration = 0

    try:
        while args.count == 0 or iteration < args.count:
            iteration += 1
            print(f"\n=== Snapshot {iteration} at {time.strftime('%Y-%m-%d %H:%M:%S')} ===")
            print_socket_rows(read_netstat(labels, ports))
            sniff_packets(args.interface, ports, args.sniff, labels)

            if args.count == 0 or iteration < args.count:
                time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nStopped.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())