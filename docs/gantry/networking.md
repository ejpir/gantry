# Networking

Each network-enabled sandbox connects to a userspace IPv4 stack. Gantry
enforces egress policy below the guest, publishes selected host ports, and can
route proxy-aware applications through an upstream proxy.

## Default network policy

Networking is enabled by default. A sandbox can reach the public IPv4
internet, but Gantry denies local and special-use destinations unless you opt
in. The denied ranges include:

- RFC 1918 private networks;
- link-local addresses, including `169.254.169.254` cloud metadata;
- loopback, CGNAT, multicast, and reserved ranges;
- the host alias used by the userspace network.

The guest's ARP, valid DHCP client traffic, and DNS to the embedded gateway
remain available so the link can operate. Other gateway ports follow the
ordinary local-network policy, and non-DHCP broadcast traffic is denied.

To disable the network completely:

```console
$ gantry start offline -image alpine:latest -net=false
```

To allow local destinations explicitly:

```console
$ gantry start lan -image alpine:latest -allow-local-net
```

> [!WARNING]
> `-allow-local-net` exposes host and LAN services to the guest. Enable it only
> when the workload needs that access.

## Define an egress policy

A policy contains an ordered list of IP, protocol, and port rules plus an
optional DNS allowlist. The first matching explicit rule wins.

This policy denies by default, allows HTTPS to one subnet, denies a sensitive
address inside that subnet, and permits two domain names:

```json
{
  "default": "deny",
  "allowLocal": false,
  "rules": [
    {
      "action": "deny",
      "cidr": "203.0.113.10/32"
    },
    {
      "action": "allow",
      "cidr": "203.0.113.0/24",
      "proto": "tcp",
      "ports": "443"
    }
  ],
  "allowDomains": [
    "api.example.com",
    "*.packages.example.com"
  ]
}
```

Supported rule protocols are `any`, `tcp`, `udp`, and `icmp`. `ports` accepts
individual ports, comma-separated ports, and ranges such as `8000-9000`.

Start with the policy:

```console
$ gantry start restricted -image alpine:latest -net-policy ./policy.json
```

Apply or replace a policy on an existing sandbox:

```console
$ gantry net-policy set restricted ./policy.json
$ gantry net-policy show restricted
```

Return to Gantry's built-in public-internet policy:

```console
$ gantry net-policy default restricted
```

For a stopped sandbox, these commands update the saved configuration for its
next start. For a running embedded-network sandbox, the change applies to
subsequent packets without a reboot.

## Understand domain allowlists

When `allowDomains` is non-empty, the gateway DNS resolver filters queries by
name. Gantry observes permitted DNS answers and temporarily allows their IPv4
addresses, capped by the DNS TTL and an internal maximum.

Domain policy is convenient, but the DNS name is not carried in ordinary IP
packets. An application that already knows an address is governed by the
explicit IP rules and default action. Use `"default": "deny"` when a domain
allowlist is intended to constrain egress.

Gantry's embedded guest network is IPv4-only. Non-IPv4 traffic is denied.

## Publish ports

Publish a guest service when creating the sandbox:

```console
$ gantry start web -image nginx:alpine -p 8080:80
```

The default bind address is `127.0.0.1`. To expose the service on every host
interface, write that intent explicitly:

```console
$ gantry start web -image nginx:alpine -p 0.0.0.0:8080:80
```

Supported forms are:

```text
8080:80              host 127.0.0.1:8080 -> guest 80/tcp
127.0.0.1:8080:80    explicit host bind address
[::1]:5353:53/udp    IPv6 host listener -> guest IPv4 UDP port
80                   choose a free host port -> guest 80/tcp
```

TCP publishes work with the default local-network wall: Gantry admits only
handshake-tracked replies for the exact gateway-to-guest connection. UDP has
no equivalent handshake, so a UDP publish is accepted only when the active
egress policy already permits the virtual gateway's full ephemeral reply
range, `192.168.127.1:16000-65535/udp`. The default policy does not. Granting
that range (or using `-allow-local-net` with a default-allow policy) is an
explicit widening of guest-to-gateway access.

Add, inspect, or remove a forward while the sandbox is running:

```console
$ gantry ports publish web 8081:80
$ gantry ports ls web
$ gantry ports unpublish web 8081:80
```

Live changes are saved to `sandbox.json` and re-applied after restart. Add
`--ephemeral` to change only the current boot.

Port publishing requires networking and the embedded network stack. It is
unavailable with `-net=false`; the legacy external `-gvproxy` backend is
disabled.

## Use an upstream proxy

Set a proxy URL when the sandbox starts:

```console
$ gantry start dev -image alpine:latest \
    -proxy http://proxy.example:3128
```

Supported URL schemes are `http`, `https`, `socks5`, and `socks5h`. SOCKS
URLs require an explicit port. Proxy credentials cannot be stored in the
sandbox configuration URL; inject authenticated proxy variables as secrets
instead.

Gantry injects upper- and lower-case `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`,
and `NO_PROXY` variables into guest processes. The default bypass list is
`localhost,127.0.0.1,::1`; override it with `-no-proxy`.

Environment variables guide proxy-aware software but do not force all
traffic through the proxy. Add `-proxy-enforce` to deny direct TCP 80/443 and
UDP 443 while allowing the resolved proxy address and port:

```console
$ gantry start dev -image alpine:latest \
    -proxy http://proxy.example:3128 \
    -proxy-enforce
```

Proxy enforcement requires the embedded network stack. It does not block
direct traffic on unrelated ports; combine it with a default-deny policy for
a strict egress posture.

## Inspect traffic

The terminal dashboard records bounded per-sandbox traffic summaries,
including destination addresses, observed DNS names, protocols, ports, byte
counts, and policy decisions. From the Traffic view you can add or remove
policy overrides.

The Packets view starts a bounded, in-memory capture at the virtual Ethernet
boundary. Captures are for live diagnosis and are not written as a general
packet log.
