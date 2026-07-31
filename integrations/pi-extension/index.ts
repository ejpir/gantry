/**
 * Gantry Tool Routing — run pi's commands inside a gantry microVM.
 *
 * One `gantry start` per pi session (~60 ms boot); every bash tool call is
 * a `gantry exec <name> -- sh -lc ...` into the running sandbox (docker-exec
 * semantics, real exit codes, SIGINT → broker kill). The host working
 * directory is shared into the guest and mounted at /workspace in the
 * container; file changes write through to the host.
 *
 * File tools (read/write/edit/grep/find/ls) stay host-side — the share is
 * the same directory — but are confined to the workspace root, the same
 * split Claude Code uses: policy-constrained file ops, VM-constrained
 * code execution.
 *
 * Setup:
 *   cd integrations/pi-extension && npm install --ignore-scripts
 *
 * Usage:
 *   cd /path/to/project
 *   pi -e /path/to/minivm/integrations/pi-extension
 *
 * Per-project config (.pi/gantry.json):
 *   {
 *     "image": "alpine:latest",        // OCI ref, OCI layout dir, or .erofs
 *     "gantry": "gantry",              // binary (default: PATH)
 *     "netPolicy": "allow-github.json",// gantry -net-policy file
 *     "secrets": ["GITHUB_TOKEN"],     // gantry -secret names
 *     "mem": 1024, "cpus": 2, "rw": true
 *   }
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";
import {
	type BashOperations,
	createBashTool,
	createEditTool,
	createFindTool,
	createGrepTool,
	createLsTool,
	createReadTool,
	createWriteTool,
} from "@earendil-works/pi-coding-agent";

const GUEST_WORKSPACE = "/workspace";

type GantryConfig = {
	image?: string;
	gantry?: string;
	netPolicy?: string;
	secrets?: string[];
	rw?: boolean;
	mem?: number;
	cpus?: number;
};

function loadConfig(localCwd: string): GantryConfig {
	try {
		return JSON.parse(fs.readFileSync(path.join(localCwd, ".pi", "gantry.json"), "utf8"));
	} catch {
		return {};
	}
}

function isInsideHostPath(root: string, value: string): boolean {
	const rel = path.relative(root, value);
	return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function toPosix(value: string): string {
	return value.split(path.sep).join(path.posix.sep);
}

// Map a host path to the guest: inside the workspace → /workspace/...,
// anything else stays absolute (the guest's own disposable rootfs).
function toGuestPath(localCwd: string, hostPath: string): string {
	if (isInsideHostPath(localCwd, hostPath)) {
		const rel = path.relative(localCwd, hostPath);
		return rel ? path.posix.join(GUEST_WORKSPACE, toPosix(rel)) : GUEST_WORKSPACE;
	}
	return path.posix.resolve("/", toPosix(hostPath));
}

// File-tool confinement: every path-ish argument must resolve inside the
// workspace (bash has no such rule — it executes inside the VM anyway).
function assertInsideWorkspace(localCwd: string, value: string): void {
	const stripped = value.startsWith("@") ? value.slice(1) : value;
	if (!stripped) return;
	const resolved = path.resolve(localCwd, stripped);
	if (!isInsideHostPath(localCwd, resolved)) {
		throw new Error(
			`path "${value}" is outside the sandboxed workspace ${localCwd} ` +
				`(use bash for guest-side paths, or add a ro share to .pi/gantry.json)`,
		);
	}
}

function confineParams(localCwd: string, params: Record<string, unknown>): void {
	for (const key of ["path", "cwd", "dir", "file", "filePath"]) {
		const v = params[key];
		if (typeof v === "string" && v) assertInsideWorkspace(localCwd, v);
	}
}

type RunResult = { code: number | null; stderr: string };

function run(cmd: string, args: string[]): Promise<RunResult> {
	return new Promise((resolve, reject) => {
		const child = spawn(cmd, args, { stdio: ["ignore", "ignore", "pipe"] });
		let stderr = "";
		child.stderr.on("data", (d) => (stderr += d));
		child.on("error", reject);
		child.on("close", (code) => resolve({ code, stderr }));
	});
}

export default function (pi: ExtensionAPI) {
	const localCwd = process.cwd();
	const cfg = loadConfig(localCwd);
	const gantry = cfg.gantry ?? process.env.GANTRY ?? "gantry";
	const name = `pi-${process.pid}`;

	const localRead = createReadTool(localCwd);
	const localWrite = createWriteTool(localCwd);
	const localEdit = createEditTool(localCwd);
	const localBash = createBashTool(localCwd);
	const localGrep = createGrepTool(localCwd);
	const localFind = createFindTool(localCwd);
	const localLs = createLsTool(localCwd);

	let shellPath = "/bin/sh";
	let ready = false;
	let starting: Promise<void> | undefined;

	async function startSandbox(ctx?: ExtensionContext): Promise<void> {
		ctx?.ui.setStatus("gantry", ctx.ui.theme.fg("accent", `Gantry: starting ${name}`));
		await run(gantry, ["delete", name]); // no-op unless a zombie is left
		const args = ["start", name, "-image", cfg.image ?? "alpine:latest", "-share", `ws=${localCwd}`];
		if (cfg.rw) args.push("-rw=true");
		if (cfg.mem) args.push("-mem", String(cfg.mem));
		if (cfg.cpus) args.push("-cpus", String(cfg.cpus));
		if (cfg.netPolicy) args.push("-net-policy", cfg.netPolicy);
		for (const s of cfg.secrets ?? []) args.push("-secret", s);
		const res = await run(gantry, args);
		if (res.code !== 0) {
			throw new Error(`gantry start failed:\n${res.stderr.trim()}`);
		}
		// pick the shell the IMAGE actually has (alpine has no bash)
		const probe = await run(gantry, ["exec", name, "--", "sh", "-lc", "command -v bash || command -v sh"]);
		if (probe.code === 0) {
			const out = await shellProbe();
			shellPath = out || "/bin/sh";
		}
		ready = true;
		ctx?.ui.setStatus("gantry", ctx.ui.theme.fg("accent", `Gantry: ${name} (${GUEST_WORKSPACE})`));
		ctx?.ui.notify(`Gantry sandbox ${name} up. ${localCwd} is mounted at ${GUEST_WORKSPACE}.`, "info");
	}

	function shellProbe(): Promise<string> {
		return new Promise((resolve) => {
			const child = spawn(gantry, ["exec", name, "--", "sh", "-lc", "command -v bash || command -v sh"]);
			let out = "";
			child.stdout.on("data", (d) => (out += d));
			child.on("close", () => resolve(out.trim().split("\n")[0] ?? ""));
			child.on("error", () => resolve(""));
		});
	}

	async function ensureSandbox(ctx?: ExtensionContext): Promise<void> {
		if (ready) return;
		if (!starting) {
			starting = startSandbox(ctx).finally(() => {
				starting = undefined;
			});
		}
		return starting;
	}

	function createGantryBashOps(): BashOperations {
		return {
			exec: async (command, cwd, { onData, signal, timeout }) => {
				if (signal?.aborted) throw new Error("aborted");
				await ensureSandbox();
				const guestCwd = toGuestPath(localCwd, cwd);
				// $0/$1 keep guestCwd and command as separate argv — no
				// quoting hazards, no shell re-parsing of the command.
				const child = spawn(
					gantry,
					["exec", name, "--", "sh", "-c", 'cd "$0" && exec "$1" -lc "$2"', guestCwd, shellPath, command],
					{ stdio: ["ignore", "pipe", "pipe"] },
				);
				child.stdout.on("data", onData);
				child.stderr.on("data", onData);

				let timedOut = false;
				const timer =
					timeout && timeout > 0
						? setTimeout(() => {
								timedOut = true;
								child.kill("SIGINT"); // gantry exec turns SIGINT into a broker kill
								setTimeout(() => child.kill("SIGKILL"), 3000);
							}, timeout * 1000)
						: undefined;
				const onAbort = () => child.kill("SIGINT");
				signal?.addEventListener("abort", onAbort, { once: true });

				try {
					const code = await new Promise<number | null>((resolve, reject) => {
						child.on("error", reject);
						child.on("close", resolve);
					});
					if (signal?.aborted) throw new Error("aborted");
					if (timedOut) throw new Error(`timeout:${timeout}`);
					return { exitCode: code ?? 1 };
				} finally {
					if (timer) clearTimeout(timer);
					signal?.removeEventListener("abort", onAbort);
				}
			},
		};
	}

	pi.on("session_start", async (_event, ctx) => {
		try {
			await ensureSandbox(ctx);
		} catch (err) {
			ctx.ui.notify(`Gantry sandbox failed to start: ${err}`, "error");
		}
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		if (!ready) return;
		ready = false;
		ctx.ui.setStatus("gantry", ctx.ui.theme.fg("muted", "Gantry: stopping"));
		try {
			await run(gantry, ["delete", name]);
		} finally {
			ctx.ui.setStatus("gantry", undefined);
		}
	});

	pi.registerCommand("gantry", {
		description: "Show gantry sandbox status",
		handler: async (_args, ctx) => {
			await ensureSandbox(ctx);
			ctx.ui.notify(
				[`Sandbox: ${name}`, `Host workspace: ${localCwd}`, `Guest workspace: ${GUEST_WORKSPACE}`, `Shell: ${shellPath}`].join(
					"\n",
				),
				"info",
			);
		},
	});

	// Code execution: inside the VM.
	pi.registerTool({
		...localBash,
		async execute(id, params, signal, onUpdate, ctx) {
			await ensureSandbox(ctx);
			const tool = createBashTool(GUEST_WORKSPACE, { operations: createGantryBashOps() });
			return tool.execute(id, params, signal, onUpdate);
		},
	});

	// File tools: host-side (the share is the same directory), confined
	// to the workspace root.
	for (const tool of [localRead, localWrite, localEdit, localLs, localFind, localGrep]) {
		pi.registerTool({
			...tool,
			execute(id, params, signal, onUpdate) {
				confineParams(localCwd, params as Record<string, unknown>);
				return tool.execute(id, params, signal, onUpdate);
			},
		});
	}

	pi.on("user_bash", async (_event, ctx) => {
		await ensureSandbox(ctx);
		return { operations: createGantryBashOps() };
	});

	pi.on("before_agent_start", async (event, ctx) => {
		await ensureSandbox(ctx);
		const localLine = `Current working directory: ${localCwd}`;
		const guestLine =
			`Current working directory: ${GUEST_WORKSPACE} (gantry VM ${name}; ` +
			`host workspace shared from ${localCwd}). The bash tool executes INSIDE the VM; ` +
			`read/write/edit/grep/find/ls operate on the shared workspace and are confined to it.`;
		const systemPrompt = event.systemPrompt.includes(localLine)
			? event.systemPrompt.replace(localLine, guestLine)
			: `${event.systemPrompt}\n\n${guestLine}`;
		return { systemPrompt };
	});
}
