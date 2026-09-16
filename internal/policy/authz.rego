package gantry

import rego.v1

# This module is shipped, not supplied by bundles. Local policy is enforced
# independently; it can narrow but never widen these organization decisions.
default decision := {"effect": "deny", "reason": "no_match", "rules": []}

decision := {"effect": "deny", "reason": "explicit_deny", "rules": sort(denied)} if {
    count(denied) > 0
} else := {"effect": "allow", "reason": "explicit_allow", "rules": sort(allowed)} if {
    count(allowed) > 0
} else := {"effect": "allow", "reason": "dns_allow", "rules": []} if {
    input.action == "network.resolve"
    some domain in data.profile.network.dns
    host_matches(domain, input.resource.host)
}

denied contains r.id if {
    some r in data.profile.rules
    r.effect == "deny"
    matches(r)
}
allowed contains r.id if {
    some r in data.profile.rules
    r.effect == "allow"
    matches(r)
}
denied contains r.id if {
    input.action == "network.connect"
    some r in data.profile.network.rules
    r.effect == "deny"
    network_matches(r)
}
allowed contains r.id if {
    input.action == "network.connect"
    some r in data.profile.network.rules
    r.effect == "allow"
    network_matches(r)
}

matches(r) if {
    r.action == input.action
    r.action in {"mount.read", "mount.write"}
    beneath(input.resource.path, r.path)
}
# Exporting a parent also exposes denied descendants. Checking only whether
# the requested root is beneath the denial would leave an ancestor bypass.
matches(r) if {
    r.action == input.action
    r.action in {"mount.read", "mount.write"}
    r.effect == "deny"
    beneath(r.path, input.resource.path)
}
matches(r) if {
    r.action == input.action
    r.action in {"mcp.tools.list", "mcp.tools.call"}
    name_matches(r.server, input.resource.server)
    name_matches(r.tool, input.resource.tool)
}
matches(r) if {
    r.action == input.action
    r.action == "mcp.connect"
    name_matches(r.server, input.resource.server)
}
matches(r) if {
    r.action == input.action
    r.action == "credential.use"
    host_matches(r.host, input.resource.host)
}

beneath(value, root) if { value == root }
beneath(value, root) if { startswith(value, concat("", [trim_suffix(root, "/"), "/"])) }
name_matches(pattern, value) if { pattern == value }
name_matches(pattern, value) if {
    endswith(pattern, "*")
    startswith(value, trim_suffix(pattern, "*"))
}
host_matches(pattern, value) if { pattern == "*" }
host_matches(pattern, value) if { pattern == value }
host_matches(pattern, value) if {
    startswith(pattern, "*.")
    value == trim_prefix(pattern, "*.")
}
host_matches(pattern, value) if {
    startswith(pattern, "*.")
    endswith(value, trim_prefix(pattern, "*"))
}
network_matches(r) if {
    net.cidr_contains(r.cidr, input.resource.ip)
    r.protocol in {"any", input.resource.protocol}
    ports_match(r.ports)
}
ports_match(ports) if { count(ports) == 0 }
ports_match(ports) if { input.resource.port in ports }

network_plan := {
    "organization": data.meta.organization,
    "revision": data.meta.revision,
    "expires_at": data.meta.expires_at,
    "rules": data.profile.network.rules,
    "dns": data.profile.network.dns,
}
