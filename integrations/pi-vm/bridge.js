#!/usr/bin/env node
/**
 * pi-bridge — runs INSIDE the gantry VM as the exec target for
 *   pi attach --cmd "gantry exec <vm> -- node /opt/pi/bridge.js"
 *
 * Two jobs:
 *  1. Ensure the pi RPC agent is serving on a guest-local unix socket
 *     (started once, survives detach — reattach reconnects, takeover
 *     semantics come from the RPC server's single-client rule).
 *  2. Pipe this process's stdio <-> the agent socket, so the host-side
 *     attach client speaks the RPC protocol over the gantry exec pipe.
 *
 * Optional /etc/pi-bridge.env (KEY=VALUE lines) augments the agent's
 * environment — e.g. HTTPS_PROXY=http://192.168.1.1:3128 behind a
 * corporate proxy. Written once via gantry exec, persists in the rwlayer.
 */
"use strict";

const net = require("node:net");
const fs = require("node:fs");
const { spawn } = require("node:child_process");

const DIR = "/tmp/pi-attach";
const SOCK = `${DIR}/agent.sock`;
const LOG = `${DIR}/agent.log`;
const CLI = "/opt/pi/repo/packages/coding-agent/dist/cli.js";
const AGENT_CWD = process.env.PI_WORKSPACE || "/workspace";

function loadEnvFile() {
	let text;
	try {
		text = fs.readFileSync("/etc/pi-bridge.env", "utf8");
	} catch {
		return;
	}
	for (const line of text.split("\n")) {
		const m = line.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/);
		if (m && !(m[1] in process.env)) process.env[m[1]] = m[2];
	}
	// Node's global fetch (undici) ignores HTTP(S)_PROXY unless told otherwise;
	// without this, proxy-only egress hangs model-catalog refreshes and other
	// fetch-based calls (the sequential RPC queue then jams behind them).
	if (!("NODE_USE_ENV_PROXY" in process.env)) process.env.NODE_USE_ENV_PROXY = "1";
}

function tryConnect() {
	return new Promise((resolve, reject) => {
		const sock = net.connect(SOCK);
		sock.once("connect", () => resolve(sock));
		sock.once("error", (err) => {
			sock.destroy();
			reject(err);
		});
	});
}

function startAgent() {
	fs.mkdirSync(DIR, { recursive: true });
	try {
		fs.unlinkSync(SOCK);
	} catch {}
	const out = fs.openSync(LOG, "a");
	const child = spawn(process.execPath, [CLI, "--mode", "rpc", "--sock", SOCK], {
		cwd: AGENT_CWD,
		detached: true,
		stdio: ["ignore", out, out],
		env: process.env,
	});
	child.unref();
}

async function ensureAgent() {
	try {
		return await tryConnect();
	} catch {
		startAgent();
	}
	for (let i = 0; i < 100; i++) {
		await new Promise((r) => setTimeout(r, 200));
		try {
			return await tryConnect();
		} catch {}
	}
	throw new Error(`pi agent did not start; see ${LOG}`);
}

async function main() {
	loadEnvFile();
	const sock = await ensureAgent();
	// Raw byte pipe both ways. If the host side goes away (detach), this
	// bridge exits — the agent keeps serving for the next attach.
	process.stdin.pipe(sock);
	sock.pipe(process.stdout);
	const bail = () => process.exit(0);
	sock.once("close", bail);
	sock.once("error", bail);
	process.stdin.once("end", () => sock.end());
}

main().catch((err) => {
	process.stderr.write(`pi-bridge: ${err.message}\n`);
	process.exit(1);
});
