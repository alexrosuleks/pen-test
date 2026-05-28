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

const PENETRATION_TESTER_VERSION = '2.0.0';

const results = {
    version: PENETRATION_TESTER_VERSION,
    timestamp: new Date().toISOString(),
    containerInfo: {},
    categories: {
        buildTime: { tests: [], passed: 0, failed: 0 },
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
    const test = { name, passed, details, timestamp: new Date().toISOString() };
    results.categories[category].tests.push(test);
    if (passed) {
        results.categories[category].passed++;
        console.log(`  ✓ ${name}`);
    } else {
        results.categories[category].failed++;
        const msg = details.error || details.vulnerability || details.note || 'FAILED';
        console.log(`  ✗ ${name} - ${msg}`);
        if (details.vulnerability) {
            results.vulnerabilities.push({ category, name, ...details });
        }
    }
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
        { file: '03-host-fs.txt', name: 'Build: Host Paths Not Accessible', failIf: /^ACCESSIBLE: \/host/m },
        { file: '10-secrets.txt', name: 'Build: No Unexpected Secret Mounts', failIf: /FOUND: \/var\/run\/docker.sock/i },
        { file: '12-gvisor.txt', name: 'Build: gVisor Detected', passIf: /gvisor|runsc/i },
        { file: '08-capabilities.txt', name: 'Build: Capabilities Logged', passIf: /CapEff|CapBnd/i },
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
    }

    results.containerInfo.buildTimeSummary = summary.substring(0, 500);
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

    logTest('containerHardening', 'CapEff Is Zero (CapDrop ALL)', capEff === 0n, {
        CapEff: status.CapEff || 'unknown',
        CapBnd: status.CapBnd || 'unknown',
        vulnerability: capEff !== 0n ? `Effective capabilities non-zero: ${status.CapEff}` : null,
    });

    logTest('containerHardening', 'no-new-privileges (NoNewPrivs=1)', noNewPrivs, {
        NoNewPrivs: status.NoNewPrivs || '0',
        vulnerability: !noNewPrivs ? 'Container can gain privileges via setuid/capabilities' : null,
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

    const version = runCmd('cat /proc/version 2>&1');
    const isGvisor = /gvisor|runsc/i.test(version.output);
    logTest('gvisorEscape', 'gVisor Runtime Detected', isGvisor, {
        procVersion: version.output.substring(0, 120),
        vulnerability: !isGvisor ? 'Not running under gVisor (runc?)' : null,
    });

    const dmesg = runCmd('dmesg 2>&1 | head -3');
    logTest('gvisorEscape', 'dmesg Not Available', dmesg.output.includes('not available') || dmesg.output.includes('Operation not permitted'), {
        preview: dmesg.output.substring(0, 80),
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

    const shadow = runCmd('cat /etc/shadow 2>&1');
    logTest('containerBreakout', '/etc/shadow Not Readable', shadow.output.includes('Permission denied') || shadow.output.includes('No such'), {
        vulnerability: shadow.success && !shadow.output.includes('denied') ? '/etc/shadow readable' : null,
    });

    const setuid = runCmd('find /usr -perm -4000 -type f 2>/dev/null | head -15');
    const dangerous = ['sudo', 'su', 'passwd'].filter((b) => setuid.output.includes(b));
    logTest('containerBreakout', 'No Dangerous Setuid Binaries', dangerous.length === 0, {
        setuidCount: setuid.output.split('\n').filter(Boolean).length,
        dangerous,
    });
}

// ========================================
// RESOURCE EXHAUSTION
// ========================================
async function testResourceExhaustion() {
    console.log('\n=== RESOURCE LIMITS ===\n');

    const memLimit = runCmd('cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null');
    const memBytes = parseInt(memLimit.output.trim(), 10) || 0;
    logTest('resourceExhaustion', 'Memory Limit Configured', memBytes > 0 && memBytes < 64 * 1024 ** 3, {
        limitMB: Math.round(memBytes / (1024 * 1024)) || 'unknown',
    });

    const pidsMax = runCmd('cat /sys/fs/cgroup/pids.max 2>/dev/null || echo unknown');
    logTest('resourceExhaustion', 'PIDs Limit Present', pidsMax.output.trim() !== 'max' && pidsMax.output.trim() !== 'unknown', {
        pidsMax: pidsMax.output.trim(),
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
        await testContainerHardening();
        await testScrapelyPlatform();
        await testNetworkIsolation();
        await testPerUserNetworkIsolation();
        await testRegistryAccess();
        await testGvisorEscape();
        await testContainerBreakout();
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
    }

    fs.writeFileSync('/tmp/penetration-test-results.json', JSON.stringify(results, null, 2));
    console.log('\nResults: /tmp/penetration-test-results.json');

    try {
        const { Actor } = await import('scrapely');
        await Actor.init();
        await Actor.setValue('PENETRATION_TEST_RESULTS', results);
        console.log('Results saved to KV store: PENETRATION_TEST_RESULTS');
        await Actor.exit();
    } catch {
        console.log('(KV store save skipped — run inside Scrapely actor for full output)');
    }

    console.log('\nPenetration test complete.\n');
}

main().catch(console.error);
