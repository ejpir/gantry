#!/usr/bin/env node
/**
 * relay.js <listen-spec> <connect-spec> — bidirectional byte pipe.
 * Spec is either a unix socket path ("/tmp/x.sock") or "host:port".
 *
 * Used to carry pi's unix-socket RPC transport across the container
 * boundary on platforms where bind-mounted unix sockets don't work
 * (macOS Docker Desktop / podman machine):
 *   container:  relay.js 0.0.0.0:7680 /tmp/agent.sock     (TCP → unix)
 *   mac host:   relay.js /tmp/pi-attach/agent.sock 127.0.0.1:7680  (unix → TCP)
 */
const net = require("node:net");
const fs = require("node:fs");

function parse(spec) {
	if (!spec) return undefined;
	const match = spec.match(/^(.+):(\d+)$/);
	if (match && !spec.startsWith("/")) return { host: match[1], port: Number(match[2]) };
	return { path: spec };
}

const [listen, connect] = process.argv.slice(2).map(parse);
if (!listen || !connect) {
	console.error("usage: relay.js <listen /path.sock|host:port> <connect /path.sock|host:port>");
	process.exit(1);
}

const server = net.createServer((inbound) => {
	const outbound = connect.path
		? net.connect(connect.path)
		: net.connect(connect.port, connect.host);
	inbound.pipe(outbound);
	outbound.pipe(inbound);
	inbound.on("error", () => outbound.destroy());
	outbound.on("error", () => inbound.destroy());
});

if (listen.path) {
	try {
		fs.unlinkSync(listen.path);
	} catch {
		// nothing to clean
	}
	server.listen(listen.path, () => {
		fs.chmodSync(listen.path, 0o600);
		console.error(`relay listening on ${listen.path} -> ${connect.path ?? `${connect.host}:${connect.port}`}`);
	});
} else {
	server.listen(listen.port, listen.host, () => {
		console.error(`relay listening on ${listen.host}:${listen.port} -> ${connect.path}`);
	});
}
