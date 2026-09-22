#!/usr/bin/env node
// Linux/KVM capture of the real TUI, using disposable state only.
// See assets/README.md for prerequisites and the recording's scope.
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import { access, copyFile, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

const repo = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { values } = parseArgs({ options: {
  assets: { type: 'string', default: process.env.GANTRY_ARTIFACTS || path.join(repo, 'artifacts') },
  output: { type: 'string', default: path.join(repo, 'assets/gantry-tui-v3') },
  chrome: { type: 'string', default: process.env.CHROME_BIN || '/opt/google/chrome/chrome' },
  font: { type: 'string', default: '/usr/share/fonts/TTF/DejaVuSansMono.ttf' },
  keep: { type: 'boolean', default: false },
  help: { type: 'boolean', default: false },
} });
if (values.help) {
  console.log(`Usage: node scripts/record-tui-demo.mjs [options]
  --assets DIR    Staged kernel, rootfs and default Alpine image (default: artifacts/)
  --output PATH   Output prefix for .webm, .mp4, .gif and .png (default: assets/gantry-tui-v3)
  --chrome PATH   Chrome/Chromium executable (or CHROME_BIN)
  --font PATH     DejaVu Sans Mono TTF
  --keep          Retain temporary frames and isolated state for debugging

Requires Linux/KVM, Go, Node/npm, Python 3, ffmpeg, Chrome and a monospace font.
Installs pinned capture-only npm dependencies into a temporary directory.
Builds current sources, creates two disposable VMs, makes sample HTTP requests,
records 24 seconds at native 2× resolution / 10 fps, and stops the VMs.
Exports lossless RGB VP9, H.264, a 256-color GIF, and a PNG poster.
Does not use your Gantry state or tokens.`);
  process.exit(0);
}
if (process.platform !== 'linux' || !['x64', 'arm64'].includes(process.arch)) {
  throw new Error('This recording recipe requires Linux x86-64 or ARM64 with KVM.');
}
const arch = process.arch === 'x64' ? 'x86_64' : 'arm64';
const assets = path.resolve(values.assets);
const output = path.resolve(values.output);
const fps = 10;
const deviceScaleFactor = 2;
const sources = [
  `gantry-kernel-${arch}`,
  `nerdbox-rootfs-${arch}.erofs`,
  `gantry-default-image-${arch}.erofs`,
];
await access('/dev/kvm', constants.R_OK | constants.W_OK);
for (const filename of sources) await access(path.join(assets, filename));
await access(values.chrome, constants.X_OK);
await access(values.font);

function run(file, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { cwd: repo, stdio: 'inherit', ...options });
    child.once('error', reject);
    child.once('exit', (code, signal) => code === 0 ? resolve() : reject(new Error(`${file} exited ${code ?? signal}`)));
  });
}
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
const scratch = await mkdtemp(path.join(tmpdir(), 'gantry-demo-'));
const binary = path.join(scratch, 'gantry');
const frames = path.join(scratch, 'frames');
const home = path.join(scratch, 'home');
const workspace = path.join(scratch, 'workspace');
const env = { ...process.env, HOME: home, GANTRY_HOME: path.join(home, 'sandboxes'),
  GANTRY_ARTIFACTS: scratch, GANTRY_REMOTE: '', TERM: 'xterm-256color', COLORTERM: 'truecolor' };
let browser, server, terminal;
let interrupted = false;
const traffic = [];
// Let normal cleanup stop only our demo VMs even when interrupted.
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => { interrupted = true; });
try {
  console.log(`Capture workspace: ${scratch}`);
  for (const dir of [home, workspace, frames]) await mkdir(dir, { mode: 0o700 });
  await mkdir(path.dirname(output), { recursive: true });
  for (const filename of sources) await symlink(path.join(assets, filename), path.join(scratch, filename));
  await symlink(path.join(scratch, sources[2]), path.join(scratch, 'alpine.erofs'));
  await copyFile(values.font, path.join(scratch, 'capture-mono.ttf'));
  await writeFile(path.join(workspace, 'README.md'), '# Example workspace\n\nDisposable data for the Gantry terminal recording.\n');
  const policy = path.join(scratch, 'agent-policy.json');
  await writeFile(policy, JSON.stringify({ default: 'deny', allowDomains: ['dl-cdn.alpinelinux.org', 'github.com', 'api.github.com'], rules: [] }));
  await run('go', ['build', '-o', binary, './cmd/gantry']);
  await run('go', ['build', '-trimpath', '-o', path.join(scratch, `gantry-guest-${arch}`), './cmd/gantry-guest'], { env: { ...process.env, CGO_ENABLED: '0' } });
  await run('npm', ['install', '--prefix', scratch, '--no-audit', '--no-fund', '--no-package-lock', '@xterm/xterm@6.0.0', 'playwright@1.63.0']);
  const { chromium } = await import(pathToFileURL(path.join(scratch, 'node_modules/playwright/index.mjs')).href);
  const gantry = args => run(binary, args, { env });
  if (interrupted) throw new Error('Capture interrupted');
  await gantry(['start', 'workspace', '-image', path.join(scratch, 'alpine.erofs'), '-cpus', '2', '-mem', '1024', '-ssh', '-share', `workspace=${workspace},mount=/workspace`]);
  await gantry(['start', 'agent', '-image', path.join(scratch, 'alpine.erofs'), '-net-policy', policy,
    '-share', `code=${workspace},mount=/workspace,ro,uid=1000,gid=1000`, '-mcp', '-mcp-fs-root', '/workspace', '-mcp-fs-user', '1000:1000']);
  // Real allowed requests and a policy-denied request, not invented counters.
  await gantry(['exec', 'workspace', '--', '/bin/sh', '-c', 'wget -q -T 5 -O /dev/null https://example.com; true']);
  await gantry(['exec', 'agent', '--', '/bin/sh', '-c', 'wget -q -T 5 -O /dev/null https://dl-cdn.alpinelinux.org/alpine/; wget -q -T 2 -O /dev/null https://example.com; true']);
  for (const [name, command] of [
    ['workspace', 'wget -q -T 3 -O /dev/null https://example.com; sleep 2'],
    ['agent', 'wget -q -T 3 -O /dev/null https://dl-cdn.alpinelinux.org/alpine/; wget -q -T 2 -O /dev/null https://example.com; sleep 1'],
  ]) {
    traffic.push(spawn(binary, ['exec', name, '--', '/bin/sh', '-c', `for i in 1 2 3 4 5 6 7 8 9 10 11 12; do ${command}; done`], { env, stdio: 'ignore' }));
  }

  // A real POSIX PTY drives the unmodified binary; xterm renders its ANSI output.
  await writeFile(path.join(scratch, 'pty_bridge.py'), `import fcntl, os, pty, select, signal, struct, subprocess, sys, termios
master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 36, 132, 0, 0))
def session():
    os.setsid()
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)
def interrupted(signum, frame):
    raise SystemExit(1)
signal.signal(signal.SIGTERM, interrupted)
p = subprocess.Popen(sys.argv[1:], stdin=slave, stdout=slave, stderr=slave, preexec_fn=session)
os.close(slave)
try:
    while p.poll() is None:
        ready, _, _ = select.select([master, sys.stdin.buffer], [], [], .1)
        if master in ready:
            try: data = os.read(master, 65536)
            except OSError: break
            if not data: break
            sys.stdout.buffer.write(data)
            sys.stdout.buffer.flush()
        if sys.stdin.buffer in ready:
            data = os.read(sys.stdin.fileno(), 4096)
            if not data: break
            os.write(master, data)
finally:
    if p.poll() is None:
        p.terminate()
        try: p.wait(timeout=3)
        except subprocess.TimeoutExpired: p.kill(); p.wait()
    os.close(master)
`);
  await writeFile(path.join(scratch, 'terminal.html'), `<!doctype html><meta charset="utf-8">
<link rel="stylesheet" href="/xterm.css"><style>
@font-face{font-family:CaptureMono;src:url(/capture-mono.ttf)}
*{box-sizing:border-box}html,body{margin:0;background:#101210;overflow:hidden}
#terminal{padding:12px;width:max-content}.xterm-viewport{overflow:hidden!important}.xterm .xterm-cursor-layer{visibility:hidden}
</style><div id="terminal"></div><script src="/xterm.js"></script><script>
window.ready=(async()=>{await document.fonts.load('14px CaptureMono');window.term=new Terminal({cols:132,rows:36,fontFamily:'CaptureMono, monospace',fontSize:14,lineHeight:1.15,cursorBlink:false,scrollback:0,theme:{background:'#101210',foreground:'#f0f1e9',cursor:'#101210'}});term.open(document.getElementById('terminal'));term.onData(data=>window.terminalInput(data));})();
</script>`);
  const served = new Map([
    ['/terminal.html', ['terminal.html', 'text/html']],
    ['/capture-mono.ttf', ['capture-mono.ttf', 'font/ttf']],
    ['/xterm.js', ['node_modules/@xterm/xterm/lib/xterm.js', 'text/javascript']],
    ['/xterm.css', ['node_modules/@xterm/xterm/css/xterm.css', 'text/css']],
  ]);
  server = createServer(async (req, res) => {
    try {
      const [filename, mime] = served.get(req.url) || [];
      if (!filename) return res.writeHead(404).end();
      res.setHeader('Content-Type', mime);
      res.end(await readFile(path.join(scratch, filename)));
    } catch { res.writeHead(500).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  browser = await chromium.launch({ executablePath: path.resolve(values.chrome), headless: true });
  // Render fonts at the output pixel density; do not enlarge a 1× bitmap.
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 }, deviceScaleFactor });
  await page.exposeFunction('terminalInput', data => { if (terminal?.stdin.writable) terminal.stdin.write(data); });
  await page.goto(`http://127.0.0.1:${server.address().port}/terminal.html`);
  await page.evaluate(() => window.ready);
  terminal = spawn('python3', [path.join(scratch, 'pty_bridge.py'), binary, 'tui', '-remote='], { env, stdio: ['pipe', 'pipe', 'inherit'] });
  let pending = [];
  terminal.stdout.on('data', data => pending.push(data));
  async function pump() {
    if (interrupted) throw new Error('Capture interrupted');
    if (terminal.exitCode !== null) throw new Error(`TUI exited unexpectedly: ${terminal.exitCode}`);
    if (!pending.length) return;
    const data = Buffer.concat(pending).toString('base64');
    pending = [];
    await page.evaluate(data => new Promise(resolve => term.write(Uint8Array.from(atob(data), c => c.charCodeAt(0)), resolve)), data);
  }
  async function wait(ms) {
    const until = Date.now() + ms;
    do { await pump(); await sleep(30); } while (Date.now() < until);
  }
  const text = () => page.evaluate(() => Array.from({ length: term.rows }, (_, i) => term.buffer.active.getLine(i)?.translateToString(true) || '').join('\n'));
  async function waitFor(expected) {
    for (let attempt = 0; attempt < 80; attempt++) {
      await wait(100);
      if ((await text()).includes(expected)) return;
    }
    throw new Error(`TUI did not display ${expected}\n${await text()}`);
  }
  await waitFor('TRAFFIC TOTALS');
  const view = page.locator('#terminal');
  let frame = 0;
  // 24 seconds at the capture frame rate. Discard short view-loading transitions.
  for (const [key, expected, seconds] of [
    ['', 'TRAFFIC TOTALS', 3.6], ['1', 'microVM boundary', 3.6], ['e', 'Edit Sandbox', 3],
    ['\x1b2', 'HOST / DESTINATION', 3.6], ['3', 'public internet', 3],
    ['4', 'HOST PATH', 2.6], ['7', 'built-in read-only filesystem', 2.6], ['0', 'TRAFFIC TOTALS', 2],
  ]) {
    // Escape must be delivered alone so it cannot be interpreted as Alt+2.
    if (key.startsWith('\x1b')) { terminal.stdin.write('\x1b'); await wait(300); }
    if (key) terminal.stdin.write(key.replace('\x1b', ''));
    await waitFor(expected);
    await wait(200);
    for (let i = 0; i < Math.round(seconds * fps); i++) {
      const start = Date.now();
      await pump();
      await view.screenshot({ path: path.join(frames, `${String(frame++).padStart(4, '0')}.png`), scale: 'device' });
      await wait(Math.max(0, 1000 / fps - (Date.now() - start)));
    }
  }
  const input = ['-hide_banner', '-loglevel', 'warning', '-y', '-framerate', String(fps), '-i', path.join(frames, '%04d.png')];
  // RGB VP9 preserves the source pixels: no palette reduction or chroma subsampling.
  await run('ffmpeg', [...input, '-c:v', 'libvpx-vp9', '-lossless', '1', '-pix_fmt', 'gbrp',
    '-colorspace', 'rgb', '-color_range', 'pc', '-row-mt', '1', '-threads', '4', '-cpu-used', '4', '-an', `${output}.webm`]);
  // Broadly compatible fallback for browsers without RGB VP9 support.
  await run('ffmpeg', [...input, '-c:v', 'libx264', '-preset', 'slow', '-crf', '14', '-pix_fmt', 'yuv420p',
    '-movflags', '+faststart', '-an', `${output}.mp4`]);
  // Preserve static text colors too; avoid dithering speckle around glyph edges.
  await run('ffmpeg', [...input, '-filter_complex',
    '[0:v]split[a][b];[a]palettegen=max_colors=256:stats_mode=full[p];[b][p]paletteuse=dither=none:diff_mode=rectangle', '-loop', '0', `${output}.gif`]);
  await copyFile(path.join(frames, `${String(frame - 8).padStart(4, '0')}.png`), `${output}.png`);
  console.log(`Recorded ${frame / fps}s at ${deviceScaleFactor}×: ${output}.{webm,mp4,gif,png}`);
} finally {
  if (terminal) {
    terminal.stdin.end('q');
    await Promise.race([new Promise(resolve => terminal.once('exit', resolve)), sleep(1000)]);
    if (terminal.exitCode === null) terminal.kill('SIGTERM');
  }
  for (const child of traffic) if (child.exitCode === null) child.kill('SIGTERM');
  for (const name of ['agent', 'workspace']) {
    await run(binary, ['stop', name], { env, stdio: 'ignore' }).catch(() => {});
  }
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
  if (values.keep) console.log(`Kept ${scratch}`);
  else await rm(scratch, { recursive: true, force: true });
}
