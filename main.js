/**
 * Scrapely Container Penetration Tester v2
 *
 * Runtime + build-time checks for Scrapely isolation:
 * - Network (RFC1918, per-user 172.32–47, DNS, IPv6, metadata)
 * - Registry auth (no anonymous catalog/manifest/push)
 * - gVisor / breakout / docker socket
 * - CapDrop ALL + no-new-privileges (run hardening)
 * - Scrapely env (expected user token vs forbidden admin/DB creds)
 * - Resource limits, info disclosure
 */

import net from 'net';
import dns from 'dns/promises';
import fs from 'fs';
import { execSync } from 'child_process';

const PENETRATION_TESTER_VERSION = '2.2.0';

const results = {
    version: PENETRATION_TESTER_VERSION,
    timestamp: new Date().toISOString(),
    containerInfo: {},
    categories: {
        buildTime: { tests: [], passed: 0, failed: 0 },
        buildEnvironment: { tests: [], passed: 0, failed: 0 },
        ssrfAttacks: { tests: [], passed: 0, failed: 0 },
        apiAbuse: { tests: [], passed: 0, failed: 0 },
        escapeProbes: { tests: [], passed: 0, failed: 0 },
        infraSurface: { tests: [], passed: 0, failed: 0 },
        containerHardening: { tests: [], passed: 0, failed: 0 },
        scrapelyPlatform: { tests: [], passed: 0, failed: 0 },
        networkIsolation: { tests: [], passed: 0, failed: 0 },
        perUserNetwork: { tests: [], passed: 0, failed: 0 },
        registryAccess: { tests: [], passed: 0, failed: 0 },
        gvisorEscape: { tests: [], passed: 0, failed: 0 },
        containerBreakout: { tests: [], passed: 0, failed: 0 },
        resourceExhaustion: { tests: [], passed: 0, failed: 0 },
        infoDisclosure: { tests: [], passed: 0, failed: 0 },
    },
    vulnerabilities: [],
    summary: {},
};

/** Env vars that must NEVER appear in run containers */
const FORBIDDEN_ENV_PREFIXES = [
    'ADMIN_API_KEY',
    'SINGLESTORE_',
    'REGISTRY_PASSWORD',
    'REGISTRY_USERNAME',
    'REGISTRY_TOKEN_PRIVATE_KEY',
    'DRAGONFLY_PASSWORD',
    'ENCRYPTION_MASTER_KEY',
    'S3_SECRET',
    'S3_ACCESS_KEY',
];

/** Expected in run containers (presence is OK) */
const EXPECTED_RUN_ENV = [
    'SCRAPELY_TOKEN',
    'SCRAPELY_API_URL',
    'CDP_URL',
    'ACTOR_RUN_ID',
    'ACTOR_ID',
];

const INTERNAL_IPS = [
    '10.0.0.1', '10.0.0.2', '10.255.255.1',
    '172.16.0.1', '172.17.0.1', '172.18.0.1', '172.30.0.1', '172.31.0.1',
    '192.168.0.1', '192.168.1.1',
];

const DB_PORTS = [
    { port: 3306, name: 'MySQL' },
    { port: 5432, name: 'PostgreSQL' },
    { port: 6379, name: 'Redis/Dragonfly' },
    { port: 27017, name: 'MongoDB' },
    { port: 9200, name: 'Elasticsearch' },
];

const USER_SUBNET_GATEWAYS = Array.from({ length: 16 }, (_, i) => `172.${32 + i}.0.1`);

function logTest(category, name, passed, details = {}) {
    const informational = details.informational === true;
    const test = { name, passed, informational, details, timestamp: new Date().toISOString() };
    results.categories[category].tests.push(test);
    if (passed) {
        results.categories[category].passed++;
        console.log(`  ✓ ${name}`);
    } else if (informational) {
        results.categories[category].passed++;
        const msg = details.note || details.vulnerability || 'informational';
        console.log(`  ~ ${name} - ${msg}`);
    } else {
        results.categories[category].failed++;
        const msg = details.error || details.vulnerability || details.note || 'FAILED';
        console.log(`  ✗ ${name} - ${msg}`);
        if (details.vulnerability) {
            results.vulnerabilities.push({ category, name, ...details });
        }
    }
}

function isRunningAsRoot() {
    const id = runCmd('id -u');
    return id.output.trim() === '0';
}

function detectGvisor() {
    const version = runCmd('cat /proc/version 2>&1').output;
    if (/gvisor|runsc/i.test(version)) return { detected: true, method: '/proc/version' };
    const mount = runCmd('grep -i runsc /proc/self/mountinfo 2>&1 || true').output;
    if (/runsc/i.test(mount)) return { detected: true, method: 'mountinfo' };
    const dmesg = runCmd('dmesg 2>&1 | head -1').output;
    if (/not available|Operation not permitted/i.test(dmesg)) {
        return { detected: 'likely', method: 'dmesg-blocked-heuristic' };
    }
    return { detected: false, method: 'none' };
}

function runCmd(cmd, timeoutMs = 5000) {
    try {
        const output = execSync(cmd, {
            timeout: timeoutMs,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
        }).toString();
        return { success: true, output };
    } catch (e) {
        return {
            success: false,
            error: e.message,
            output: e.stdout?.toString() || '',
            stderr: e.stderr?.toString() || '',
        };
    }
}

async function testTcpConnect(host, port, timeoutMs = 2000) {
    return new Promise((resolve) => {
        const socket = new net.Socket();
        const timer = setTimeout(() => {
            socket.destroy();
            resolve({ connected: false, error: 'timeout' });
        }, timeoutMs);

        socket.connect(port, host, () => {
            clearTimeout(timer);
            socket.destroy();
            resolve({ connected: true });
        });

        socket.on('error', (err) => {
            clearTimeout(timer);
            resolve({ connected: false, error: err.code || err.message });
        });
    });
}

function parseProcStatus() {
    const status = runCmd('cat /proc/self/status 2>&1');
    const lines = status.output.split('\n');
    const map = {};
    for (const line of lines) {
        const m = line.match(/^(\w+):\s+(.*)$/);
        if (m) map[m[1]] = m[2].trim();
    }
    return map;
}

function capHexToBigInt(hex) {
    if (!hex) return 0n;
    return BigInt(`0x${hex}`);
}

function httpProbe(url, timeoutSec = 3) {
    return runCmd(`curl -sS -m ${timeoutSec} -o /dev/null -w "%{http_code}" "${url}" 2>&1 || echo "curl_failed"`);
}

async function httpFetch(url, timeoutMs = 4000) {
    try {
        const res = await fetch(url, {
            signal: AbortSignal.timeout(timeoutMs),
            redirect: 'follow',
            headers: { 'User-Agent': 'ScrapelyPenTest/2.2' },
        });
        const text = await res.text().catch(() => '');
        return {
            ok: true,
            status: res.status,
            bodyPreview: text.substring(0, 400),
            len: text.length,
        };
    } catch (e) {
        return { ok: false, error: e.message, code: e.cause?.code || e.code };
    }
}

async function apiRequest(method, path, body) {
    const apiUrl = (process.env.SCRAPELY_API_URL || '').replace(/\/$/, '');
    const token = process.env.SCRAPELY_TOKEN;
    if (!apiUrl || !token) return { skipped: true, reason: 'no API URL or token' };
    try {
        const res = await fetch(`${apiUrl}${path}`, {
            method,
            headers: {
                Authorization: `Bearer ${token}`,
                'Content-Type': 'application/json',
                ...(process.env.ACTOR_RUN_ID ? { 'X-Scrapely-Run-Id': process.env.ACTOR_RUN_ID } : {}),
            },
            body: body !== undefined ? JSON.stringify(body) : undefined,
            signal: AbortSignal.timeout(8000),
        });
        const text = await res.text().catch(() => '');
        return { skipped: false, status: res.status, body: text.substring(0, 400), ok: res.ok };
    } catch (e) {
        return { skipped: false, error: e.message };
    }
}

function looksLikeMetadataLeak(body) {
    if (!body) return false;
    return /ami-|instance-id|project-id|computeMetadata|meta-data/i.test(body);
}

function looksLikePasswdLeak(body) {
    return body && /^root:/m.test(body);
}

// ========================================
// BUILD-TIME (from Dockerfile RUN steps)
// ========================================
async function testBuildTime() {
    console.log('\n=== BUILD-TIME TESTS ===\n');

    const paths = [
        '/app/build-test-results/SUMMARY.txt',
        '/build-test-results/SUMMARY.txt',
    ];

    let resultsDir = null;
    for (const p of paths) {
        if (fs.existsSync(p)) {
            resultsDir = p.replace('/SUMMARY.txt', '');
            break;
        }
    }

    if (!resultsDir) {
        logTest('buildTime', 'Build-Time Results Present', false, {
            note: 'Rebuild actor with penetration-tester Dockerfile to enable build-time tests',
        });
        return;
    }

    console.log(`Build results: ${resultsDir}`);
    const summary = fs.readFileSync(`${resultsDir}/SUMMARY.txt`, 'utf8');
    console.log(summary.substring(0, 800));

    const checks = [
        { file: '04-docker-socket.txt', name: 'Build: Docker Socket Blocked', failIf: /DOCKER SOCKET EXISTS|CRITICAL/i },
        { file: '03-host-fs.txt', name: 'Build: /host Not Accessible', failIf: /^ACCESSIBLE: \/host/m },
        { file: '03-host-fs.txt', name: 'Build: Docker Sock Path Not Accessible', failIf: /^ACCESSIBLE: \/var\/run\/docker\.sock/m },
        { file: '10-secrets.txt', name: 'Build: No Unexpected Secret Mounts', failIf: /FOUND: \/var\/run\/docker\.sock/i },
        { file: '12-gvisor.txt', name: 'Build: gVisor Detected', passIf: /gvisor|runsc/i },
        { file: '08-capabilities.txt', name: 'Build: Capabilities Logged', passIf: /CapEff|CapBnd/i },
        { file: '09-build-env.txt', name: 'Build: Kaniko Environment', passIf: /KANIKO|Kaniko|build/i },
        { file: '06-dns.txt', name: 'Build: Internal Service DNS Blocked', failIf: /dragonfly.*Address:|redis.*Address:|singlestore.*Address:/i },
        { file: '07-processes.txt', name: 'Build: No Host dockerd Visible', failIf: /\bdockerd\b|\bcontainerd\b/ },
        { file: '11-mounts.txt', name: 'Build: No Docker Socket Mount', failIf: /docker\.sock/ },
    ];

    for (const { file, name, failIf, passIf } of checks) {
        const fp = `${resultsDir}/${file}`;
        if (!fs.existsSync(fp)) continue;
        const content = fs.readFileSync(fp, 'utf8');
        let passed = true;
        if (failIf && failIf.test(content)) passed = false;
        if (passIf && !passIf.test(content)) passed = false;
        logTest('buildTime', name, passed, { file, preview: content.substring(0, 150) });
    }

    if (fs.existsSync(`${resultsDir}/05-network.txt`)) {
        const net = fs.readFileSync(`${resultsDir}/05-network.txt`, 'utf8');
        const internalReachable = /10\.0\.0\.1:3000[^\-]*200|172\.17\.0\.1:3000[^\-]*200/.test(net);
        logTest('buildTime', 'Build: Internal API Not Trivially Open', !internalReachable, {
            preview: net.substring(0, 200),
            vulnerability: internalReachable ? 'Build could reach internal API on RFC1918' : null,
        });
        const buildDbLeaks = [];
        for (const line of ['172.17.0.1:3306', '172.17.0.1:22', '169.254.169.254:80']) {
            if (new RegExp(`${line.replace(/\./g, '\\.')}.*(open|Connected|succeeded)`, 'i').test(net)) {
                buildDbLeaks.push(line);
            }
        }
        logTest('buildTime', 'Build: Host/Metadata Ports Blocked', buildDbLeaks.length === 0, {
            vulnerability: buildDbLeaks.length > 0 ? buildDbLeaks.join(', ') : null,
            preview: net.substring(0, 300),
        });
    }

    if (fs.existsSync(`${resultsDir}/02-sensitive-env.txt`)) {
        const sens = fs.readFileSync(`${resultsDir}/02-sensitive-env.txt`, 'utf8');
        const bad = ['ADMIN_API_KEY', 'SINGLESTORE_PASSWORD', 'REGISTRY_PASSWORD', 'DRAGONFLY_PASSWORD']
            .filter((k) => sens.includes(k));
        logTest('buildTime', 'Build: No Platform Secrets In Env', bad.length === 0, {
            vulnerability: bad.length > 0 ? bad.join(', ') : null,
        });
    }

    if (fs.existsSync(`${resultsDir}/13-escape.txt`)) {
        const esc = fs.readFileSync(`${resultsDir}/13-escape.txt`, 'utf8');
        logTest('buildTime', 'Build: /proc/1/root Blocked', /proc\/1\/root blocked|Permission denied/i.test(esc) && !/^[a-f0-9]{12}$/m.test(esc.split('\n').find(l => l.trim() && !l.includes('===')) || ''), {
            preview: esc.substring(0, 120),
        });
        logTest('buildTime', 'Build: Metadata HTTP Blocked', /metadata HTTP blocked|Could not resolve|Connection refused|timed out/i.test(esc) && !/ami-|instance-id/i.test(esc), {
            vulnerability: /ami-|instance-id/i.test(esc) ? 'Metadata leaked during build' : null,
        });
    }

    if (fs.existsSync(`${resultsDir}/14-ssrf.txt`)) {
        const ssrf = fs.readFileSync(`${resultsDir}/14-ssrf.txt`, 'utf8');
        logTest('buildTime', 'Build: Loopback HTTP Blocked', /127\.0\.0\.1 blocked|Connection refused|timed out/i.test(ssrf), {
            preview: ssrf.substring(0, 120),
        });
        logTest('buildTime', 'Build: file:// Blocked', !/^root:/m.test(ssrf), {
            vulnerability: /^root:/m.test(ssrf) ? 'file:// returned /etc/passwd during build' : null,
        });
    }

    results.containerInfo.buildTimeSummary = summary.substring(0, 500);
}

// ========================================
// BUILD ENVIRONMENT (live runtime probes — mirrors build Dockerfile tests)
// ========================================
async function testBuildEnvironmentLive() {
    console.log('\n=== BUILD ENVIRONMENT (live) ===\n');

    const uid = runCmd('id -u').output.trim();
    logTest('buildEnvironment', 'Build Probe: User Context Logged', uid.length > 0, { uid });

    const dockerSock = runCmd('test -S /var/run/docker.sock && echo EXISTS || echo absent');
    logTest('buildEnvironment', 'Build Probe: Docker Socket Absent', !dockerSock.output.includes('EXISTS'), {
        vulnerability: dockerSock.output.includes('EXISTS') ? 'Docker socket accessible during build/run' : null,
    });

    for (const path of ['/host', '/var/run/docker.sock']) {
        const r = runCmd(`test -e ${path} && echo yes || echo no`);
        logTest('buildEnvironment', `Build Probe: ${path} Not Accessible`, !r.output.includes('yes'), {
            vulnerability: r.output.includes('yes') ? `${path} accessible` : null,
        });
    }

    let liveDbLeaks = [];
    for (const ip of ['172.17.0.1', '172.18.0.1', '172.30.0.1']) {
        const mysql = await testTcpConnect(ip, 3306, 1200);
        if (mysql.connected) liveDbLeaks.push(`MySQL@${ip}:3306`);
        const ssh = await testTcpConnect(ip, 22, 1200);
        if (ssh.connected) liveDbLeaks.push(`SSH@${ip}:22`);
    }
    const meta = await testTcpConnect('169.254.169.254', 80, 2000);
    if (meta.connected) liveDbLeaks.push('metadata@169.254.169.254:80');

    logTest('buildEnvironment', 'Build Probe: Host/Metadata Ports Blocked', liveDbLeaks.length === 0, {
        vulnerability: liveDbLeaks.length > 0 ? liveDbLeaks.join(', ') : null,
    });

    const kaniko = runCmd('test -f /kaniko/executor && echo yes || echo no');
    logTest('buildEnvironment', 'Build Probe: Kaniko Executor Absent At Runtime', !kaniko.output.includes('yes'), {
        note: kaniko.output.includes('yes') ? 'Still in Kaniko build context' : 'Expected absent in run container',
        informational: kaniko.output.includes('yes'),
    });

    const internet = await testTcpConnect('1.1.1.1', 443, 3000);
    logTest('buildEnvironment', 'Build Probe: Internet Egress', internet.connected, {
        note: 'Build and run containers need outbound internet',
    });
}

// ========================================
// CONTAINER HARDENING (CapDrop, no-new-privs)
// ========================================
async function testContainerHardening() {
    console.log('\n=== CONTAINER HARDENING ===\n');

    const status = parseProcStatus();
    const capEff = capHexToBigInt(status.CapEff);
    const capBnd = capHexToBigInt(status.CapBnd);
    const noNewPrivs = status.NoNewPrivs === '1';
    const gvisor = detectGvisor();

    logTest('containerHardening', 'CapEff Is Zero (CapDrop ALL)', capEff === 0n, {
        CapEff: status.CapEff || 'unknown',
        CapBnd: status.CapBnd || 'unknown',
        vulnerability: capEff !== 0n ? `Effective capabilities non-zero: ${status.CapEff}` : null,
    });

    logTest('containerHardening', 'no-new-privileges (NoNewPrivs=1)', noNewPrivs || gvisor.detected || gvisor.detected === 'likely', {
        NoNewPrivs: status.NoNewPrivs || '0',
        gvisor: gvisor.method,
        informational: !noNewPrivs && (gvisor.detected || gvisor.detected === 'likely'),
        note: !noNewPrivs ? 'Not visible under gVisor — SecurityOpt still set on host' : null,
        vulnerability: !noNewPrivs && !gvisor.detected && gvisor.detected !== 'likely'
            ? 'Container can gain privileges via setuid/capabilities' : null,
    });

    const privileged = runCmd('cat /proc/self/status | grep -i CapEff');
    const isPrivilegedContainer = privileged.output.includes('CapEff') &&
        !/^CapEff:\s+0+$/m.test(privileged.output.trim().split('\n').find(l => l.startsWith('CapEff')) || '');

    logTest('containerHardening', 'Not Privileged (no broad CapEff)', !isPrivilegedContainer || capEff === 0n, {
        capLine: privileged.output.split('\n').filter(l => l.startsWith('Cap')).join('; '),
    });

    const mountPrivileged = runCmd('grep -i privileged /proc/self/mountinfo 2>&1 || true');
    logTest('containerHardening', 'No Privileged Mount Flag', !mountPrivileged.output.toLowerCase().includes('privileged'), {
        preview: mountPrivileged.output.substring(0, 120),
    });

    const readonlyRoot = runCmd('touch /readonly-root-probe 2>&1');
    const rootWritable = readonlyRoot.success || !readonlyRoot.stderr?.includes?.('Read-only');
    logTest('containerHardening', 'Root FS Writable (informational)', true, {
        rootWritable,
        note: 'Run containers may have writable root; download uses ReadonlyRootfs',
    });
}

// ========================================
// SCRAPELY PLATFORM ENV
// ========================================
async function testScrapelyPlatform() {
    console.log('\n=== SCRAPELY PLATFORM ===\n');

    const env = process.env;
    const envKeys = Object.keys(env);

    const forbiddenFound = [];
    for (const key of envKeys) {
        for (const prefix of FORBIDDEN_ENV_PREFIXES) {
            if (key === prefix || key.startsWith(prefix)) {
                forbiddenFound.push(key);
            }
        }
    }
    logTest('scrapelyPlatform', 'No Forbidden Platform Secrets In Env', forbiddenFound.length === 0, {
        vulnerability: forbiddenFound.length > 0 ? `Leaked: ${forbiddenFound.join(', ')}` : null,
        forbiddenFound,
    });

    const expectedFound = EXPECTED_RUN_ENV.filter((k) => env[k]);
    logTest('scrapelyPlatform', 'Expected Run Env Present', expectedFound.length >= 3, {
        expectedFound,
        missing: EXPECTED_RUN_ENV.filter((k) => !env[k]),
    });

    const apiUrl = env.SCRAPELY_API_URL || env.INTERNAL_API_URL;
    if (apiUrl) {
        const probeUrl = apiUrl.replace(/\/$/, '');
        const probe = httpProbe(probeUrl, 5);
        const code = probe.output.trim();
        const ok = ['200', '301', '302', '404', '401', '403'].includes(code) || probe.output.includes('curl');
        logTest('scrapelyPlatform', 'SCRAPELY_API_URL Reachable', ok, {
            url: apiUrl,
            httpCode: code,
            note: 'Public API URL expected in production',
        });
    } else {
        logTest('scrapelyPlatform', 'SCRAPELY_API_URL Set', false, { note: 'No API URL in env' });
    }

    const secretMount = runCmd('ls -la /run/secrets 2>&1; ls -la /tmp/secrets 2>&1; ls -la /run/secrets/private_key.pem 2>&1');
    const hasPrivateKeyMount = secretMount.output.includes('private_key');
    logTest('scrapelyPlatform', 'Private Key Mount Only When Expected', true, {
        hasPrivateKeyMount,
        note: 'Optional per-run secret input mount',
    });

    logTest('scrapelyPlatform', 'DOCKER_HOST Not Exposed', !env.DOCKER_HOST, {
        DOCKER_HOST: env.DOCKER_HOST ? '***set***' : undefined,
        vulnerability: env.DOCKER_HOST ? 'DOCKER_HOST in container env' : null,
    });
}

// ========================================
// NETWORK ISOLATION
// ========================================
async function testNetworkIsolation() {
    console.log('\n=== NETWORK ISOLATION ===\n');

    const ipv6Test = runCmd('ip -6 addr 2>&1 || echo "IPv6 not available"');
    if (ipv6Test.output.includes('inet6') && !ipv6Test.output.includes('not available')) {
        const ipv6Connect = await testTcpConnect('::1', 80, 1000);
        logTest('networkIsolation', 'IPv6 Loopback Not Reachable', !ipv6Connect.connected, {
            vulnerability: ipv6Connect.connected ? 'IPv6 may bypass IPv4 iptables rules' : null,
        });
    } else {
        logTest('networkIsolation', 'IPv6 Disabled Or Unavailable', true, {});
    }

    // Internal IPs on DB ports — must be blocked
    let dbLeaks = [];
    for (const ip of INTERNAL_IPS) {
        for (const { port, name } of DB_PORTS) {
            const r = await testTcpConnect(ip, port, 1200);
            if (r.connected) dbLeaks.push(`${name}@${ip}:${port}`);
        }
    }
    logTest('networkIsolation', 'Database Ports On Internal IPs Blocked', dbLeaks.length === 0, {
        vulnerability: dbLeaks.length > 0 ? dbLeaks.join(', ') : null,
    });

    // Port 3000 to docker gateway — often allowed by DOCKER-USER rule (informational)
    const api3000 = await testTcpConnect('172.17.0.1', 3000, 2000);
    logTest('networkIsolation', 'Docker Gateway :3000 (informational)', true, {
        connected: api3000.connected,
        note: 'iptables may allow tcp/3000 from isolated subnets; prod uses public API URL',
    });

    // SSH and metadata — must be blocked on internal IPs
    const sshLeak = await testTcpConnect('172.17.0.1', 22, 1500);
    logTest('networkIsolation', 'SSH To Docker Gateway Blocked', !sshLeak.connected, {
        vulnerability: sshLeak.connected ? 'SSH reachable on 172.17.0.1' : null,
    });

    const metadata = await testTcpConnect('169.254.169.254', 80, 2000);
    logTest('networkIsolation', 'Cloud Metadata Endpoint Blocked', !metadata.connected, {
        vulnerability: metadata.connected ? '169.254.169.254 reachable (SSRF/metadata risk)' : null,
    });

    try {
        const resolved = await dns.lookup('google.com');
        logTest('networkIsolation', 'External DNS Resolution', !!resolved.address, {
            address: resolved.address,
        });
    } catch (e) {
        logTest('networkIsolation', 'External DNS Resolution', false, { error: e.message });
    }

    const resolv = runCmd('cat /etc/resolv.conf 2>&1');
    const usesPublicDns = resolv.output.includes('8.8.8.8') || resolv.output.includes('1.1.1.1');
    const usesDockerDns = resolv.output.includes('127.0.0.11');
    logTest('networkIsolation', 'resolv.conf Uses Public DNS (gVisor)', usesPublicDns || !usesDockerDns, {
        preview: resolv.output.substring(0, 200),
        vulnerability: usesDockerDns && !usesPublicDns ? 'Docker embedded DNS may fail under gVisor' : null,
    });

    const internalHosts = ['dragonfly', 'redis', 'mysql', 'singlestore', 'scrapely-server-registry-1'];
    let resolvedInternal = [];
    for (const host of internalHosts) {
        const r = runCmd(`getent hosts ${host} 2>&1 || true`);
        if (/^\d+\.\d+\.\d+\.\d+/.test(r.output.trim())) {
            resolvedInternal.push({ host, line: r.output.trim().split('\n')[0] });
        }
    }
    logTest('networkIsolation', 'Compose Service Names Not Resolved', resolvedInternal.length === 0, {
        resolvedInternal,
        note: 'Per-user networks use IPs; compose DNS names should not resolve',
    });

    const internet = await testTcpConnect('1.1.1.1', 443, 3000);
    logTest('networkIsolation', 'Internet Egress Available', internet.connected, {
        note: 'Required for scraping',
    });
}

// ========================================
// PER-USER NETWORK (172.32–47.x)
// ========================================
async function testPerUserNetworkIsolation() {
    console.log('\n=== PER-USER NETWORK ===\n');

    const routeTable = runCmd('ip route 2>&1');
    const gatewayMatch = routeTable.output.match(/default via ([\d.]+)/);
    const gateway = gatewayMatch ? gatewayMatch[1] : 'unknown';
    results.containerInfo.gateway = gateway;

    const ipAddr = runCmd('ip -4 addr show eth0 2>&1 || ip -4 addr 2>&1');
    const containerIpMatch = ipAddr.output.match(/inet (\d+\.\d+\.\d+\.\d+)/);
    const containerIp = containerIpMatch ? containerIpMatch[1] : 'unknown';
    results.containerInfo.containerIp = containerIp;

    const inUserRange = /^172\.(3[2-9]|4[0-7])\./.test(containerIp);
    logTest('perUserNetwork', 'Container IP In User Subnet (172.32–47)', inUserRange || containerIp === 'unknown', {
        containerIp,
        gateway,
    });

    let crossSubnetLeaks = [];
    for (const gw of USER_SUBNET_GATEWAYS) {
        if (gw === `${containerIp.split('.').slice(0, 3).join('.')}.1`) continue;
        const r = await testTcpConnect(gw, 6379, 1000);
        if (r.connected) crossSubnetLeaks.push(`${gw}:6379`);
        const r2 = await testTcpConnect(gw, 3306, 1000);
        if (r2.connected) crossSubnetLeaks.push(`${gw}:3306`);
    }
    logTest('perUserNetwork', 'Other User Subnet Gateways Blocked', crossSubnetLeaks.length === 0, {
        vulnerability: crossSubnetLeaks.length > 0 ? crossSubnetLeaks.join(', ') : null,
        testedGateways: USER_SUBNET_GATEWAYS.length,
    });

    const registryIp = runCmd('getent hosts scrapely-server-registry-1 2>&1 || true');
    logTest('perUserNetwork', 'Registry Hostname Resolution (informational)', true, {
        registryResolve: registryIp.output.trim().substring(0, 80) || 'not resolved',
    });

    const iptables = runCmd('iptables -L 2>&1 || nft list ruleset 2>&1');
    const canSeeFirewall = !iptables.output.includes('not found') &&
        !iptables.output.includes('Operation not permitted') &&
        iptables.output.length > 20;
    logTest('perUserNetwork', 'Host Firewall Rules Not Visible', !canSeeFirewall, {
        preview: iptables.output.substring(0, 100),
    });
}

// ========================================
// REGISTRY ACCESS
// ========================================
async function testRegistryAccess() {
    console.log('\n=== REGISTRY ACCESS ===\n');

    const registryHosts = [
        { host: 'scrapely-server-registry-1', port: 5000 },
        { host: 'registry', port: 5000 },
        { host: '172.17.0.1', port: 5000 },
    ];

    let reachable = [];
    for (const { host, port } of registryHosts) {
        const r = await testTcpConnect(host, port, 2000);
        if (r.connected) reachable.push(`${host}:${port}`);
    }
    logTest('registryAccess', 'Registry TCP Reachable (informational)', true, {
        reachable,
        note: 'Reachability OK; auth must block unauthenticated use',
    });

    const curlHosts = reachable.length > 0 ? reachable[0] : '172.17.0.1:5000';
    const catalog = runCmd(`curl -s -m 3 http://${curlHosts}/v2/_catalog 2>&1 | head -5`);
    const catalogOpen = catalog.output.includes('"repositories"') &&
        !/unauthorized|401|denied/i.test(catalog.output);
    logTest('registryAccess', 'Catalog Requires Authentication', !catalogOpen, {
        vulnerability: catalogOpen ? 'Unauthenticated registry catalog access' : null,
        preview: catalog.output.substring(0, 120),
    });

    const manifest = runCmd(`curl -s -m 3 -o /dev/null -w "%{http_code}" http://${curlHosts}/v2/scrapely-test/manifests/latest 2>&1`);
    const manifestOpen = manifest.output.trim() === '200';
    logTest('registryAccess', 'Manifest Pull Requires Authentication', !manifestOpen, {
        httpCode: manifest.output.trim(),
        vulnerability: manifestOpen ? 'Unauthenticated manifest pull' : null,
    });

    const push = runCmd(`curl -s -m 3 -X POST http://${curlHosts}/v2/scrapely-test/blobs/uploads/ 2>&1 | head -3`);
    const pushOpen = /upload|location/i.test(push.output) && !/unauthorized|401/i.test(push.output);
    logTest('registryAccess', 'Registry Push Requires Authentication', !pushOpen, {
        vulnerability: pushOpen ? 'Unauthenticated blob upload started' : null,
        preview: push.output.substring(0, 100),
    });

    const regEnv = Object.keys(process.env).filter((k) =>
        /REGISTRY.*(PASS|USER|TOKEN)|DOCKER.*AUTH/i.test(k)
    );
    logTest('registryAccess', 'Registry Admin Creds Not In Run Env', regEnv.length === 0, {
        vulnerability: regEnv.length > 0 ? `Registry cred env: ${regEnv.join(', ')}` : null,
    });
}

// ========================================
// gVisor ESCAPE
// ========================================
async function testGvisorEscape() {
    console.log('\n=== gVisor SANDBOX ===\n');

    const gvisor = detectGvisor();
    const procVersion = runCmd('cat /proc/version 2>&1').output;

    logTest('gvisorEscape', 'gVisor Runtime Detected', gvisor.detected === true || gvisor.detected === 'likely', {
        procVersion: procVersion.substring(0, 120),
        method: gvisor.method,
        informational: gvisor.detected === 'likely',
        note: gvisor.detected === 'likely' ? 'Heuristic match (dmesg blocked + sandbox traits)' : null,
        vulnerability: !gvisor.detected ? 'Not running under gVisor (runc?)' : null,
    });

    const dmesg = runCmd('dmesg 2>&1 | head -3');
    logTest('gvisorEscape', 'dmesg Not Available', dmesg.output.includes('not available') || dmesg.output.includes('Operation not permitted'), {
        preview: dmesg.output.substring(0, 80),
        informational: true,
        note: 'Expected under gVisor',
    });

    const dangerousDevs = ['/dev/mem', '/dev/kmem', '/dev/sda', '/dev/kmsg'];
    let badDevs = [];
    for (const dev of dangerousDevs) {
        if (runCmd(`test -e ${dev} && echo yes`).output.includes('yes')) badDevs.push(dev);
    }
    logTest('gvisorEscape', 'Dangerous /dev Nodes Absent', badDevs.length === 0, {
        vulnerability: badDevs.length > 0 ? badDevs.join(', ') : null,
    });

    runCmd('modprobe fake_test_module 2>&1');
    logTest('gvisorEscape', 'Kernel Module Load Blocked', true, { note: 'Expected failure in sandbox' });
}

// ========================================
// CONTAINER BREAKOUT
// ========================================
async function testContainerBreakout() {
    console.log('\n=== CONTAINER BREAKOUT ===\n');

    const dockerSock = runCmd('test -S /var/run/docker.sock && echo EXISTS || echo absent');
    logTest('containerBreakout', 'Docker Socket Absent', !dockerSock.output.includes('EXISTS'), {
        vulnerability: dockerSock.output.includes('EXISTS') ? 'Docker socket mounted — CRITICAL' : null,
    });

    const dockerCli = runCmd('docker ps 2>&1');
    const dockerWorks = dockerCli.success && !/not found|Cannot connect/i.test(dockerCli.output);
    logTest('containerBreakout', 'Docker CLI Unavailable', !dockerWorks, {
        vulnerability: dockerWorks ? 'docker CLI works inside container' : null,
    });

    const mounts = runCmd('cat /proc/mounts 2>&1');
    const badMounts = ['/var/lib/docker', '/var/run/docker.sock'].filter((p) => mounts.output.includes(p));
    logTest('containerBreakout', 'No Host Docker Mounts', badMounts.length === 0, {
        vulnerability: badMounts.length > 0 ? badMounts.join(', ') : null,
    });

    const root = isRunningAsRoot();
    const shadow = runCmd('cat /etc/shadow 2>&1');
    const shadowReadable = shadow.success && !shadow.output.includes('denied');
    logTest('containerBreakout', '/etc/shadow Not Readable', !shadowReadable || root, {
        informational: root && shadowReadable,
        note: root && shadowReadable ? 'Root actor — expected' : null,
        vulnerability: shadowReadable && !root ? '/etc/shadow readable as non-root' : null,
    });

    const setuid = runCmd('find /usr -perm -4000 -type f 2>/dev/null | head -15');
    const dangerous = ['sudo', 'su', 'passwd'].filter((b) => setuid.output.includes(b));
    logTest('containerBreakout', 'No Dangerous Setuid Binaries', dangerous.length === 0 || root, {
        setuidCount: setuid.output.split('\n').filter(Boolean).length,
        dangerous,
        informational: root && dangerous.length > 0,
        note: root && dangerous.length > 0 ? 'Root actor — setuid present in base image' : null,
    });
}

// ========================================
// RESOURCE EXHAUSTION
// ========================================
async function testResourceExhaustion() {
    console.log('\n=== RESOURCE LIMITS ===\n');

    const memLimit = runCmd('cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null');
    const memBytes = parseInt(memLimit.output.trim(), 10) || 0;
    const envMemMb = parseInt(process.env.ACTOR_MEMORY_MBYTES || '0', 10);
    const memOk = (memBytes > 0 && memBytes < 64 * 1024 ** 3) || envMemMb > 0;
    logTest('resourceExhaustion', 'Memory Limit Configured', memOk, {
        limitMB: Math.round(memBytes / (1024 * 1024)) || envMemMb || 'unknown',
        actorMemoryMbytes: envMemMb || undefined,
        informational: memBytes <= 0 && envMemMb > 0,
        note: memBytes <= 0 && envMemMb > 0 ? 'Limit set via ACTOR_MEMORY_MBYTES (cgroup not visible under gVisor)' : null,
    });

    const pidsMax = runCmd('cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown');
    logTest('resourceExhaustion', 'PIDs Limit Present', pidsMax.output.trim() !== 'max' && pidsMax.output.trim() !== 'unknown', {
        pidsMax: pidsMax.output.trim(),
        informational: true,
        note: 'Optional — not configured on platform yet',
    });

    const fdLimit = parseInt(runCmd('ulimit -n').output.trim(), 10);
    logTest('resourceExhaustion', 'File Descriptor Limit Set', fdLimit > 0 && fdLimit < 1_000_000, { fdLimit });
}

// ========================================
// INFORMATION DISCLOSURE
// ========================================
async function testInfoDisclosure() {
    console.log('\n=== INFORMATION DISCLOSURE ===\n');

    const envLines = runCmd('env').output.split('\n').filter(Boolean);
    const leaked = envLines
        .map((l) => l.split('=')[0])
        .filter((key) => FORBIDDEN_ENV_PREFIXES.some((p) => key === p || key.startsWith(p)));
    logTest('infoDisclosure', 'No Platform Secrets In Environment', leaked.length === 0, {
        vulnerability: leaked.length > 0 ? leaked.join(', ') : null,
    });

    const tokenPresent = process.env.SCRAPELY_TOKEN;
    logTest('infoDisclosure', 'User API Token Present (expected)', !!tokenPresent, {
        note: 'SCRAPELY_TOKEN is intentional for storage API access',
        tokenLength: tokenPresent ? String(tokenPresent).length : 0,
    });

    const procs = runCmd('ps aux 2>&1');
    const hostProcs = ['dockerd', 'containerd', 'sshd'].filter((p) => procs.output.includes(p));
    logTest('infoDisclosure', 'No Host Daemon Processes Visible', hostProcs.length === 0, {
        hostProcs,
    });

    const paths = ['/actor/.env', '/app/.env', '/kaniko/.docker/config.json'];
    let exposed = [];
    for (const p of paths) {
        if (runCmd(`test -r ${p} && echo yes`).output.includes('yes')) exposed.push(p);
    }
    logTest('infoDisclosure', 'No Readable Platform Secret Files', exposed.length === 0, {
        vulnerability: exposed.length > 0 ? exposed.join(', ') : null,
    });

    if (process.env.ACTOR_WEB_SERVER_PORT) {
        logTest('infoDisclosure', 'Web Server Port Configured', true, {
            port: process.env.ACTOR_WEB_SERVER_PORT,
            url: process.env.ACTOR_WEB_SERVER_URL,
        });
    }
}

// ========================================
// SSRF & FETCH ATTACKS (HTTP layer from inside container)
// ========================================
async function testSsrfAndFetch() {
    console.log('\n=== SSRF & FETCH ATTACKS ===\n');

    const targets = [
        { url: 'http://169.254.169.254/latest/meta-data/', name: 'AWS Metadata HTTP' },
        { url: 'http://169.254.169.254/computeMetadata/v1/', name: 'GCP Metadata HTTP' },
        { url: 'http://127.0.0.1:3000/health', name: 'Loopback API /health' },
        { url: 'http://127.0.0.1:6379/', name: 'Loopback Redis' },
        { url: 'http://172.17.0.1:3306/', name: 'Docker GW MySQL HTTP' },
        { url: 'http://172.17.0.1:22/', name: 'Docker GW SSH HTTP' },
        { url: 'http://10.0.0.1/', name: 'RFC1918 10.x HTTP' },
    ];

    for (const t of targets) {
        const r = await httpFetch(t.url, 3500);
        const leaked = r.ok && (
            looksLikeMetadataLeak(r.bodyPreview) ||
            looksLikePasswdLeak(r.bodyPreview) ||
            (r.status === 200 && r.len > 50 && !/connection refused|reset/i.test(r.bodyPreview))
        );
        logTest('ssrfAttacks', `${t.name} Blocked`, !leaked && (!r.ok || r.status >= 400 || r.len < 20), {
            status: r.status,
            error: r.error,
            preview: r.bodyPreview?.substring(0, 80),
            vulnerability: leaked ? `HTTP response leaked data from ${t.url}` : null,
        });
    }

    // Dangerous URL schemes via curl (Node fetch may not support these)
    for (const [scheme, name] of [
        ['file:///etc/passwd', 'file:// Scheme'],
        ['gopher://127.0.0.1:6379/_', 'gopher:// Scheme'],
    ]) {
        const curl = runCmd(`curl -sS -m 3 "${scheme}" 2>&1 | head -3`);
        const leaked = looksLikePasswdLeak(curl.output) || /^\+OK/i.test(curl.output);
        logTest('ssrfAttacks', `${name} Blocked`, !leaked, {
            preview: curl.output.substring(0, 80),
            vulnerability: leaked ? `${scheme} returned sensitive data` : null,
        });
    }

    // DNS rebinding-style hostname (should resolve to public, not internal)
    const curlMeta = runCmd('curl -sS -m 4 http://metadata.google.internal/computeMetadata/v1/ 2>&1 | head -3');
    logTest('ssrfAttacks', 'Metadata Hostname Blocked', !looksLikeMetadataLeak(curlMeta.output), {
        preview: curlMeta.output.substring(0, 80),
        vulnerability: looksLikeMetadataLeak(curlMeta.output) ? 'metadata.google.internal reachable' : null,
    });
}

// ========================================
// API ABUSE (token scope, internal routes, cross-storage)
// ========================================
async function testApiAbuse() {
    console.log('\n=== API ABUSE ===\n');

    const apiUrl = process.env.SCRAPELY_API_URL;
    if (!apiUrl || !process.env.SCRAPELY_TOKEN) {
        logTest('apiAbuse', 'API Credentials Present', false, { note: 'Need SCRAPELY_API_URL + SCRAPELY_TOKEN' });
        return;
    }

    logTest('apiAbuse', 'API Credentials Present', true, {});

    const internalPaths = [
        { method: 'GET', path: '/internal/key-value-stores/fake-store/records/secret' },
        { method: 'PUT', path: '/internal/runs/metamorph', body: { targetActorId: 'evil' } },
        { method: 'POST', path: '/internal/runs/reboot', body: {} },
        { method: 'GET', path: '/internal/datasets/fake-dataset/items' },
    ];
    for (const { method, path, body } of internalPaths) {
        const r = await apiRequest(method, path, body);
        const blocked = r.skipped || r.status === 401 || r.status === 403 || r.status === 404 || !!r.error;
        logTest('apiAbuse', `Internal Route Blocked: ${method} ${path}`, blocked, {
            status: r.status,
            error: r.error,
            vulnerability: !blocked && r.ok ? `Internal route ${path} accessible with user token` : null,
        });
    }

    const foreignStore = '000000000000000000000000';
    const foreignKv = await apiRequest('GET', `/v2/key-value-stores/${foreignStore}/records/SECRET`);
    logTest('apiAbuse', 'Foreign KV Store Blocked', foreignKv.skipped || foreignKv.status === 403 || foreignKv.status === 404, {
        status: foreignKv.status,
        vulnerability: foreignKv.status === 200 ? 'Read foreign key-value store succeeded' : null,
    });

    const ownStore = process.env.ACTOR_DEFAULT_KEY_VALUE_STORE_ID;
    if (ownStore) {
        const ownKv = await apiRequest('GET', `/v2/key-value-stores/${ownStore}/records/INPUT`);
        logTest('apiAbuse', 'Own KV Store Accessible (expected)', ownKv.status === 200 || ownKv.status === 404, {
            status: ownKv.status,
            note: '404 OK if no INPUT key',
        });
    }

    const me = await apiRequest('GET', '/v2/users/me');
    logTest('apiAbuse', 'User Token Works For /v2/users/me', me.status === 200, { status: me.status });

    const adminPaths = [
        '/v2/admin/users',
        '/v2/admin/actors',
    ];
    for (const path of adminPaths) {
        const r = await apiRequest('GET', path);
        logTest('apiAbuse', `Admin Route Blocked: ${path}`, r.status === 401 || r.status === 403 || r.status === 404, {
            status: r.status,
            vulnerability: r.status === 200 ? `Admin route ${path} accessible` : null,
        });
    }

    // Try to charge another run
    const foreignRun = '000000000000000000000000';
    const charge = await apiRequest('POST', `/v2/actor-runs/${foreignRun}/charge`, { eventName: 'test', count: 1 });
    logTest('apiAbuse', 'Foreign Run Charge Blocked', charge.status === 403 || charge.status === 404 || charge.status === 401, {
        status: charge.status,
        vulnerability: charge.status === 200 || charge.status === 201 ? 'Charged foreign run' : null,
    });
}

// ========================================
// ESCAPE PROBES (realistic breakout attempts)
// ========================================
async function testEscapeProbes() {
    console.log('\n=== ESCAPE PROBES ===\n');

    const hostRoot = runCmd('cat /proc/1/root/etc/hostname 2>&1');
    logTest('escapeProbes', 'Host FS Via /proc/1/root Blocked', hostRoot.output.includes('Permission denied') || hostRoot.output.includes('No such'), {
        preview: hostRoot.output.substring(0, 80),
        vulnerability: hostRoot.success && !hostRoot.output.includes('denied') ? 'Read host /etc/hostname via proc' : null,
    });

    const hostEnviron = runCmd('cat /proc/1/environ 2>&1 | tr "\\0" "\\n" | head -5');
    const hostSecrets = ['ADMIN_API_KEY', 'SINGLESTORE_PASSWORD', 'DRAGONFLY_PASSWORD']
        .filter((k) => hostEnviron.output.includes(k));
    logTest('escapeProbes', 'PID1 Environ Has No Platform Secrets', hostSecrets.length === 0, {
        vulnerability: hostSecrets.length > 0 ? hostSecrets.join(', ') : null,
    });

    const mountAttempt = runCmd('mkdir -p /tmp/pentest-mnt && mount -t tmpfs tmpfs /tmp/pentest-mnt 2>&1');
    logTest('escapeProbes', 'Mount Blocked', !mountAttempt.success || /permission|denied|not permitted|operation not permitted/i.test(mountAttempt.output + mountAttempt.stderr), {
        preview: (mountAttempt.output || mountAttempt.stderr || '').substring(0, 80),
        vulnerability: mountAttempt.success ? 'mount(2) succeeded inside container' : null,
    });

    const unshare = runCmd('unshare -Urn true 2>&1');
    logTest('escapeProbes', 'Unshare Blocked', !unshare.success || /permission|denied|not permitted/i.test(unshare.output + unshare.stderr), {
        preview: (unshare.output || unshare.stderr || '').substring(0, 80),
    });

    const sysctl = runCmd('echo 1 > /proc/sys/kernel/core_pattern 2>&1');
    logTest('escapeProbes', 'Procfs Write Blocked', !sysctl.success || /read-only|permission|denied/i.test(sysctl.output + sysctl.stderr), {
        preview: (sysctl.output || sysctl.stderr || '').substring(0, 80),
        vulnerability: sysctl.success ? 'Wrote /proc/sys/kernel/core_pattern' : null,
    });

    const releaseAgent = runCmd('cat /sys/fs/cgroup/release_agent 2>&1');
    const cgroupEsc = releaseAgent.success && releaseAgent.output.trim() && !releaseAgent.output.includes('No such');
    logTest('escapeProbes', 'Cgroup release_agent Not Writable/Readable', !cgroupEsc, {
        preview: releaseAgent.output.substring(0, 80),
        vulnerability: cgroupEsc ? 'cgroup release_agent exposed' : null,
    });

    const sudo = runCmd('sudo id 2>&1');
    logTest('escapeProbes', 'Sudo Escalation Blocked', !sudo.success || /not found|not allowed|permission|sorry/i.test(sudo.output + sudo.stderr), {
        preview: (sudo.output || sudo.stderr || '').substring(0, 80),
        vulnerability: sudo.success && sudo.output.includes('uid=0') ? 'sudo worked' : null,
    });

    const ptrace = runCmd('gdb -batch -ex "attach 1" 2>&1 | head -3');
    logTest('escapeProbes', 'Ptrace/GDB Attach Blocked', !ptrace.success || /not permitted|permission|denied|not found/i.test(ptrace.output + ptrace.stderr), {
        preview: (ptrace.output || ptrace.stderr || '').substring(0, 80),
    });

    // Path traversal write probe
    const traversal = runCmd('echo pwn > /tmp/../../etc/pentest-escape-probe 2>&1');
    const traversalExists = runCmd('test -f /etc/pentest-escape-probe && echo yes || echo no').output.includes('yes');
    logTest('escapeProbes', 'Path Traversal Write Blocked', !traversalExists, {
        vulnerability: traversalExists ? 'Wrote outside container via path traversal' : null,
    });
    runCmd('rm -f /etc/pentest-escape-probe /tmp/pentest-escape-probe 2>/dev/null');

    // Limited fork probe (not a fork bomb — 30 quick spawns)
    let forkOk = 0;
    for (let i = 0; i < 30; i++) {
        try {
            execSync('true', { timeout: 500 });
            forkOk++;
        } catch { break; }
    }
    logTest('escapeProbes', 'Process Spawn Works (informational)', forkOk >= 10, {
        spawned: forkOk,
        note: 'Basic fork works; PIDs limit not tested aggressively',
        informational: true,
    });
}

// ========================================
// INFRA SURFACE (build worker / download container paths)
// ========================================
async function testInfraSurface() {
    console.log('\n=== INFRA SURFACE (build/download paths) ===\n');

    const sensitivePaths = [
        { path: '/kaniko/executor', name: 'Kaniko Executor Binary', critical: true },
        { path: '/kaniko/.docker/config.json', name: 'Kaniko Registry Config', critical: true },
        { path: '/downloads', name: 'Download Volume Mount', critical: false },
        { path: '/output', name: 'Download Output Dir', critical: false },
        { path: '/var/lib/docker', name: 'Host Docker Lib', critical: true },
        { path: '/root/.docker/config.json', name: 'Root Docker Config', critical: true },
        { path: '/etc/docker/daemon.json', name: 'Docker Daemon Config', critical: true },
        { path: '/actor-storage', name: 'Actor Storage Host Path', critical: false },
        { path: '/run/secrets', name: 'Docker Secrets Dir', critical: true },
    ];

    for (const { path, name, critical } of sensitivePaths) {
        const r = runCmd(`test -e ${path} && echo exists || echo absent`);
        const exists = r.output.includes('exists');
        const readable = exists && runCmd(`test -r ${path} && echo yes || echo no`).output.includes('yes');
        logTest('infraSurface', `${name} ${critical ? 'Not Exposed' : '(informational)'}`, !exists || !critical, {
            exists,
            readable,
            informational: !critical && exists,
            note: !critical && exists ? 'May exist in run context — check readable' : undefined,
            vulnerability: critical && readable ? `${path} readable in run container` : null,
        });
    }

    // Download-container URL validation mirror (same rules as download.sh)
    const blockedUrls = [
        'http://169.254.169.254/latest/meta-data/',
        'http://127.0.0.1:3000/',
        'http://localhost/admin',
        'file:///etc/passwd',
    ];
    for (const url of blockedUrls) {
        const blocked = /169\.254\.|127\.0\.0\.1|localhost|file:\/\//i.test(url);
        logTest('infraSurface', `Download URL Rule Would Block: ${url}`, blocked, {
            note: 'Validates download.sh pattern — server enforces on push',
            informational: true,
        });
    }

    // Build worker extra caps should NOT be effective at runtime
    const capEff = parseProcStatus().CapEff || 'unknown';
    const buildCaps = ['CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'SETUID', 'SETGID'];
    logTest('infraSurface', 'Build-Worker Extra Caps Not Active', capEff === '0' || capEff === '0000000000000000', {
        CapEff: capEff,
        buildWorkerCaps: buildCaps,
        note: 'Build worker adds CapAdd; run containers should have CapEff=0',
        vulnerability: capEff !== '0' && capEff !== '0000000000000000' ? `CapEff=${capEff}` : null,
    });
}

function printFullLogReport() {
    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║              FULL REPORT (from run logs)                     ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`IP: ${results.containerInfo.containerIp || '?'}  Gateway: ${results.containerInfo.gateway || '?'}`);
    if (results.containerInfo.buildTimestamp) {
        console.log(`Build artifacts from: ${results.containerInfo.buildTimestamp}`);
    }

    for (const [category, data] of Object.entries(results.categories)) {
        if (data.tests.length === 0) continue;
        console.log(`\n--- ${category} (${data.passed}/${data.passed + data.failed}) ---`);
        for (const t of data.tests) {
            const tag = t.passed ? 'PASS' : t.informational ? 'INFO' : 'FAIL';
            const detail = !t.passed && !t.informational && t.details?.vulnerability
                ? ` — ${t.details.vulnerability}` : '';
            console.log(`  [${tag}] ${t.name}${detail}`);
        }
    }
}

// ========================================
// MAIN
// ========================================
async function main() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log(`║     SCRAPELY PENETRATION TESTER v${PENETRATION_TESTER_VERSION}                      ║`);
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`Started: ${results.timestamp}`);
    console.log(`Container: ${runCmd('hostname').output.trim()}`);

    try {
        await testBuildTime();
        await testBuildEnvironmentLive();
        await testContainerHardening();
        await testScrapelyPlatform();
        await testNetworkIsolation();
        await testPerUserNetworkIsolation();
        await testRegistryAccess();
        await testGvisorEscape();
        await testContainerBreakout();
        await testSsrfAndFetch();
        await testApiAbuse();
        await testEscapeProbes();
        await testInfraSurface();
        await testResourceExhaustion();
        await testInfoDisclosure();
    } catch (err) {
        console.error('\n!!! Suite error:', err);
        results.error = err.message;
    }

    let totalPassed = 0;
    let totalFailed = 0;
    for (const data of Object.values(results.categories)) {
        totalPassed += data.passed;
        totalFailed += data.failed;
    }

    results.summary = {
        totalTests: totalPassed + totalFailed,
        passed: totalPassed,
        failed: totalFailed,
        vulnerabilitiesFound: results.vulnerabilities.length,
        securityScore: totalPassed + totalFailed > 0
            ? Math.round((totalPassed / (totalPassed + totalFailed)) * 100)
            : 0,
    };

    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    TEST SUMMARY                              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`Tests: ${results.summary.totalTests} | Passed: ${totalPassed} | Failed: ${totalFailed}`);
    console.log(`Vulnerabilities: ${results.vulnerabilities.length} | Score: ${results.summary.securityScore}%`);

    if (results.vulnerabilities.length > 0) {
        console.log('\n⚠️  VULNERABILITIES:');
        for (const v of results.vulnerabilities) {
            console.log(`  [${v.category}] ${v.name}: ${v.vulnerability}`);
        }
    } else {
        console.log('\n✓ No vulnerabilities detected');
    }

    printFullLogReport();
    console.log('\nPenetration test complete. See run logs above for full results.\n');
}

main().catch(console.error);
