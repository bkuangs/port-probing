# Live Connection Probe Script

The probing script is [`scripts/probe_live_connections.py`](../scripts/probe_live_connections.py). Its job is to answer three related but different questions:

```text
1. Which MAVLink Router endpoints are configured?
2. Which sockets exist, and which process owns them?
3. Which packets are actually moving right now?
```

That distinction matters because UDP has no persistent connection state. A UDP socket can be open, idle, sending one-way packets, or sending to many destinations.

## Router Config Parsing

By default, the script reads:

```text
.devcontainer/docker-builder/mavlink_router_conf/mavlink_router_conf.conf
```

It parses router sections such as:

```ini
[General]
TcpServerPort = 5761

[UdpEndpoint simulator]
Mode = server
Port = 14540
Address = 0.0.0.0

[UdpEndpoint nextvisionmock]
Mode = normal
Port = 15550
Address = 0.0.0.0
```

The parsed endpoint model contains:

```text
Endpoint name
Endpoint type, such as UdpEndpoint or TcpServer
Mode, such as server, normal, or client
Address
Port
Protocol
```

List the parsed endpoint table with:

```bash
python3 scripts/probe_live_connections.py --list-router-endpoints
```

Probe a specific endpoint by name or port:

```bash
sudo python3 scripts/probe_live_connections.py --probe-endpoint simulator --sniff 10 --interface any
sudo python3 scripts/probe_live_connections.py --find-port 15550 --sniff 10 --interface any
```

When probing an endpoint, the script prints the configured endpoint, handles the address check, shows matching sockets from `netstat`, and optionally captures traffic on that endpoint's protocol and port.

For wildcard addresses such as `0.0.0.0`, the script does not try to ping `0.0.0.0` because it is not a host. Instead, it reports local interface IPs. For real remote addresses, it attempts a one-packet `ping` check.

## Port Knowledge

The script also has a `KNOWN_PORTS` map for repo-specific labels outside the router config:

```text
4560  -> Gazebo <-> PX4 simulator TCP
15550 -> autonomy nextvisionmock UDP
15551 -> autonomy terminalguidance UDP
15552 -> autonomy mavros UDP
15553 -> GDUv2 UDP
5600  -> Gazebo camera RTP/H264 UDP video
```

Router-config labels are generated dynamically from parsed endpoints and override generic labels. Instead of only seeing `127.0.0.1:15553`, the script can say `mavlink-router GDUv2 UDP (normal)`.

## Socket Snapshot

The normal mode runs:

```bash
netstat -tunap
```

Then it parses rows whose local or remote port matches the parsed router endpoint ports, `KNOWN_PORTS`, or a custom `--ports` list.

That gives output like:

```text
tcp  127.0.0.1:4560  127.0.0.1:45520  ESTABLISHED  6586/gzserver
udp  0.0.0.0:14540   0.0.0.0:*        -            392/mavlink-routerd
```

This tells you:

```text
Protocol
Local address and port
Remote address and port, if TCP or connected UDP
TCP state, if applicable
Owning PID/process
Repo-specific port meaning
```

This mode is good for identifying owners like `px4`, `gzserver`, and `mavlink-routerd`.

## Packet Sniffing

If you pass `--sniff N`, the script uses `tcpdump` for `N` seconds:

```bash
tcpdump -i <interface> -nn -tt -q <filter>
```

The filter is generated from parsed router ports plus known repo ports, for example:

```text
tcp port 4560 or udp port 14540 or udp port 15553 ...
```

This captures actual packets, not just sockets. It is how the script can detect live traffic such as:

```text
127.0.0.1:46965 -> 127.0.0.1:5600
```

which is Gazebo camera video.

Packet sniffing usually requires root or capture permissions, so sniff mode is normally run with `sudo`.

## Owner-Outgoing Mode

The most useful mode for inspecting MAVLink Router output is:

```bash
sudo python3 scripts/probe_live_connections.py --owner-outgoing mavlink-routerd --sniff 20 --interface any
```

This mode works in three steps:

1. Run `netstat -tunap` and find sockets whose owner contains `mavlink-routerd`.
2. Extract the local source ports owned by that process, including ephemeral ports like `45198`.
3. Run `tcpdump` with a source-port filter, then summarize where packets from those ports are going.

Conceptually:

```text
Find mavlink-routerd sockets
        |
        v
Get source ports: 45198, 45713, 45766, 45947, ...
        |
        v
Capture packets where udp/tcp src port is one of those
        |
        v
Group by source -> destination
```

That is why it can output:

```text
UDP 127.0.0.1:45198 -> 127.0.0.1:15553  GDUv2 UDP
UDP 127.0.0.1:45766 -> 127.0.0.1:15551  autonomy terminalguidance UDP
UDP 127.0.0.1:45713 -> 127.0.0.1:15552  autonomy mavros UDP
UDP 127.0.0.1:45947 -> 127.0.0.1:15550  autonomy nextvisionmock UDP
```

This is different from probing one configured endpoint. Owner-outgoing mode starts from a process name and discovers where that process sends packets. Endpoint probe mode starts from the router config and checks one named endpoint's configured port.

## Why Both netstat And tcpdump

`netstat` answers ownership:

```text
Who owns port 45198? mavlink-routerd.
```

`tcpdump` answers behavior:

```text
Where is traffic from 45198 going? 127.0.0.1:15553.
```

Together they let the script say:

```text
mavlink-routerd is actively sending packets from 45198 to GDUv2 on 15553.
```

Without `tcpdump`, you would only know the socket exists. Without `netstat`, you would see packets but not confidently know which process generated them.

## Current Limitations

- It samples traffic over a time window, so quiet or bursty flows may not appear.
- It detects packet flows, not MAVLink message types. MAVLink-aware payload parsing would be needed to decode message IDs and fields.
- It labels router endpoint ports from the parsed config and known extra repo ports from `KNOWN_PORTS`; unknown ports still show, but without a friendly name.
- For UDP, `live connection` really means `live packet flow`, because UDP has no established connection state.