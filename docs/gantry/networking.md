# Networking

Each network-enabled sandbox uses a host-side userspace IPv4 stack. Gantry
filters egress, publishes selected ports, and records bounded traffic data.

## Default policy

Public IPv4 is allowed by default. Host, LAN, loopback, link-local, cloud
metadata, CGNAT, multicast, and reserved destinations are denied.

Disable networking:

```console
$ gantry start offline -image alpine:latest -net=false
```

Allow local destinations only when needed:

```console
$ gantry start lan -image alpine:latest -allow-local-net
```

> [!WARNING]
> `-allow-local-net` exposes host and LAN services to the guest.

## Define an egress policy

Rules are checked in order; the first matching rule wins. This policy allows
HTTPS to one subnet except for one address, and allows two DNS names:

```json
{
  "default": "deny",
  "rules": [
    {"action": "deny", "cidr": "203.0.113.10/32"},
    {"action": "allow", "cidr": "203.0.113.0/24", "proto": "tcp", "ports": "443"}
  ],
  "allowDomains": ["api.example.com", "*.packages.example.com"]
}
```

Protocols are `any`, `tcp`, `udp`, and `icmp`. Ports may be individual values,
comma-separated values, or ranges.

```console
$ gantry start restricted -image alpine:latest -net-policy ./policy.json
$ gantry net-policy set restricted ./policy.json
$ gantry net-policy show restricted
$ gantry net-policy default restricted
```

Changes to a running sandbox apply to new packets and persist. For a stopped
sandbox they apply at the next start.

### Domain allowlists

The gateway learns IPv4 addresses from allowed DNS answers for at most the DNS
TTL. DNS names are not present in later IP packets, so direct IP traffic still
follows explicit rules and the default action. Use `"default": "deny"` when a
domain list should constrain egress.

The embedded guest network is IPv4-only.

A signed organization policy can further restrict network access. Local rules
cannot widen it. See [Organization policy](organization-policy.md) and the
[architecture details](architecture.md#native-network-restrictions).

## Publish ports

Publish guest port 80 on host loopback port 8080:

```console
$ gantry start web -image nginx:alpine -p 8080:80
```

Common forms:

```text
8080:80              host 127.0.0.1:8080 -> guest 80/tcp
0.0.0.0:8080:80      all host interfaces -> guest 80/tcp
[::1]:5353:53/udp    IPv6 host listener -> guest IPv4 UDP port
80                   choose a free host port -> guest 80/tcp
```

Manage a running sandbox:

```console
$ gantry ports publish web 8081:80
$ gantry ports ls web
$ gantry ports unpublish web 8081:80
```

Add `--ephemeral` to avoid saving a live change. UDP publishing requires the
active policy to permit `192.168.127.1:16000-65535/udp`; Gantry rejects it
otherwise. Port publishing requires networking.

## Use a proxy

```console
$ gantry start dev -image alpine:latest -proxy http://proxy.example:3128
```

Supported schemes are `http`, `https`, `socks5`, and `socks5h`. Gantry sets
upper- and lower-case proxy variables in guest processes. The default bypass
list is `localhost,127.0.0.1,::1`; replace it with `-no-proxy`.

Proxy variables affect only proxy-aware software. Add `-proxy-enforce` to block
direct TCP 80/443 and UDP 443 except to the proxy. Combine it with a
default-deny policy for stricter egress.

## Inspect traffic

The dashboard's **Traffic** view shows bounded destination, DNS, protocol,
port, byte, and decision summaries. **Packets** starts a bounded in-memory
capture. Neither is a durable packet log.
