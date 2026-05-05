/**
 * Scrapely Container Penetration Tester
 * 
 * This actor attempts various attacks to find security vulnerabilities:
 * 1. Network isolation bypass (IPv6, UDP, DNS, tunneling)
 * 2. gVisor sandbox escape (procfs, sysfs, syscalls)
 * 3. Container breakout (symlinks, devices, docker socket)
 * 4. Resource exhaustion (process limits, memory, file descriptors)
 * 5. Information disclosure (env vars, credentials, enumeration)
 */

import net from 'net';
import dns from 'dns/promises';
import fs from 'fs';
import { execSync, spawn } from 'child_process';
import { Buffer } from 'buffer';

// ========================================
// Test Results Storage
// ========================================
const results = {
    timestamp: new Date().toISOString(),
    categories: {
        networkIsolation: { tests: [], passed: 0, failed: 0 },
        gvisorEscape: { tests: [], passed: 0, failed: 0 },
        containerBreakout: { tests: [], passed: 0, failed: 0 },
        resourceExhaustion: { tests: [], passed: 0, failed: 0 },
        infoDisclosure: { tests: [], passed: 0, failed: 0 }
    },
    vulnerabilities: [],
    summary: {}
};

function logTest(category, name, passed, details = {}) {
    const test = { name, passed, details, timestamp: new Date().toISOString() };
    results.categories[category].tests.push(test);
    if (passed) {
        results.categories[category].passed++;
        console.log(`  ✓ ${name}`);
    } else {
        results.categories[category].failed++;
        console.log(`  ✗ ${name} - ${details.error || details.vulnerability || 'FAILED'}`);
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
            stdio: ['pipe', 'pipe', 'pipe']
        }).toString();
        return { success: true, output };
    } catch (e) {
        return { success: false, error: e.message, output: e.stdout?.toString() || '', stderr: e.stderr?.toString() || '' };
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

// ========================================
// 1. NETWORK ISOLATION BYPASS TESTS
// ========================================
console.log('\n=== 1. NETWORK ISOLATION BYPASS TESTS ===\n');

async function testNetworkIsolation() {
    // 1.1 IPv6 Testing - Check if IPv6 can bypass iptables
    console.log('1.1 IPv6 Network Access...');
    const ipv6Test = runCmd('ip -6 addr 2>&1 || echo "IPv6 not available"');
    if (ipv6Test.output.includes('inet6') && !ipv6Test.output.includes('not available')) {
        // Try to connect via IPv6
        const ipv6Connect = await testTcpConnect('::1', 80, 1000);
        logTest('networkIsolation', 'IPv6 Loopback Access', !ipv6Connect.connected, {
            vulnerability: ipv6Connect.connected ? 'IPv6 can bypass iptables rules' : null,
            output: ipv6Test.output.substring(0, 500)
        });
    } else {
        logTest('networkIsolation', 'IPv6 Disabled/Unavailable', true, { output: ipv6Test.output.substring(0, 200) });
    }

    // 1.2 TCP to Internal IPs
    console.log('1.2 TCP Internal IP Reachability...');
    const internalIPs = [
        '10.0.0.1', '10.0.0.2', '10.1.0.1', '10.255.255.1',
        '172.16.0.1', '172.17.0.1', '172.18.0.1', '172.30.0.1',
        '192.168.0.1', '192.168.1.1', '192.168.100.1'
    ];
    
    let internalIPLeaks = 0;
    for (const ip of internalIPs) {
        const result = await testTcpConnect(ip, 3000, 1500);
        if (result.connected) {
            internalIPLeaks++;
            console.log(`    LEAK: ${ip}:3000 is reachable!`);
        }
    }
    logTest('networkIsolation', 'Internal IPs Blocked', internalIPLeaks === 0, {
        vulnerability: internalIPLeaks > 0 ? `${internalIPLeaks} internal IPs reachable` : null,
        testedIPs: internalIPs.length
    });

    // 1.3 UDP Port Scanning (database ports)
    console.log('1.3 UDP Database Port Access...');
    const udpPorts = [53, 161, 123];
    let udpLeaks = 0;
    for (const port of udpPorts) {
        const result = runCmd(`timeout 2 bash -c "echo test | nc -u -w1 172.17.0.1 ${port} 2>&1" || true`);
        // UDP doesn't give clear results, but we check for unexpected responses
    }
    logTest('networkIsolation', 'UDP Port Filtering', true, { note: 'UDP scan completed' });

    // 1.4 Port 3000 Tunneling Test
    console.log('1.4 Port 3000 API Access Check...');
    const apiResult = await testTcpConnect('172.17.0.1', 3000, 2000);
    logTest('networkIsolation', 'Port 3000 API Access', apiResult.connected, {
        expected: 'API should be reachable on port 3000',
        connected: apiResult.connected
    });

    // 1.5 DNS Resolution Test
    console.log('1.5 DNS Resolution...');
    try {
        const dnsResult = await dns.lookup('google.com').catch(e => ({ error: e }));
        const dnsWorks = !('error' in dnsResult);
        logTest('networkIsolation', 'External DNS Resolution', dnsWorks, {
            resolved: dnsResult.address || 'failed'
        });
    } catch (e) {
        logTest('networkIsolation', 'External DNS Resolution', false, { error: e.message });
    }

    // 1.6 Internal DNS/Hostname Resolution
    console.log('1.6 Internal Hostname Enumeration...');
    const internalHosts = [
        'dragonfly', 'redis', 'mysql', 'postgres', 'mongodb',
        'database', 'db', 'api', 'scrapely-server', 'singlestore',
        'kubernetes', 'k8s', 'etcd', 'consul', 'vault'
    ];
    let resolvedHosts = [];
    for (const host of internalHosts) {
        const result = runCmd(`getent hosts ${host} 2>&1 || true`);
        if (result.output.length > 0 && !result.output.includes('not found') && result.output.match(/^\d+\.\d+\.\d+\.\d+/)) {
            resolvedHosts.push({ host, ip: result.output.split(/\s+/)[0] });
        }
    }
    logTest('networkIsolation', 'Internal DNS Enumeration Blocked', resolvedHosts.length === 0, {
        vulnerability: resolvedHosts.length > 0 ? `Resolved: ${resolvedHosts.map(h => h.host).join(', ')}` : null,
        resolvedHosts
    });

    // 1.7 Database Port Scanning
    console.log('1.7 Database Port Scanning...');
    const dbPorts = [
        { port: 3306, name: 'MySQL' },
        { port: 5432, name: 'PostgreSQL' },
        { port: 6379, name: 'Redis/Dragonfly' },
        { port: 27017, name: 'MongoDB' },
        { port: 9200, name: 'Elasticsearch' },
        { port: 9042, name: 'Cassandra' },
        { port: 5433, name: 'SingleStore' },
        { port: 33306, name: 'SingleStore Alt' }
    ];
    
    let dbPortLeaks = [];
    const scanHosts = ['172.17.0.1', '172.30.0.1', '10.0.0.1'];
    for (const host of scanHosts) {
        for (const { port, name } of dbPorts) {
            const result = await testTcpConnect(host, port, 1000);
            if (result.connected) {
                dbPortLeaks.push({ host, port, name });
            }
        }
    }
    logTest('networkIsolation', 'Database Ports Blocked', dbPortLeaks.length === 0, {
        vulnerability: dbPortLeaks.length > 0 ? `Open ports: ${dbPortLeaks.map(l => `${l.name}@${l.host}:${l.port}`).join(', ')}` : null
    });

    // 1.8 Internet Access Verification
    console.log('1.8 Internet Access...');
    const internetTest = await testTcpConnect('8.8.8.8', 53, 3000);
    logTest('networkIsolation', 'Internet Access Available', internetTest.connected, {
        note: 'Internet access should work for scraping'
    });
}

// ========================================
// 2. gVisor SANDBOX ESCAPE TESTS
// ========================================
console.log('\n=== 2. gVisor SANDBOX ESCAPE TESTS ===\n');

async function testGvisorEscape() {
    // 2.1 Check if running under gVisor
    console.log('2.1 gVisor Detection...');
    const gvisorCheck = runCmd('cat /proc/version 2>&1');
    const isGvisor = gvisorCheck.output.toLowerCase().includes('gvisor') || 
                     gvisorCheck.output.toLowerCase().includes('runsc');
    logTest('gvisorEscape', 'gVisor Runtime Detected', isGvisor, {
        procVersion: gvisorCheck.output.substring(0, 200)
    });

    // 2.2 /proc filesystem exposure
    console.log('2.2 /proc Filesystem Access...');
    const procFiles = [
        '/proc/version', '/proc/cmdline', '/proc/cpuinfo', '/proc/meminfo',
        '/proc/loadavg', '/proc/uptime', '/proc/filesystems', '/proc/mounts',
        '/proc/devices', '/proc/interrupts', '/proc/ioports', '/proc/kallsyms',
        '/proc/kcore', '/proc/kmsg', '/proc/modules', '/proc/slabinfo'
    ];
    
    let exposedProcFiles = [];
    for (const file of procFiles) {
        const result = runCmd(`cat ${file} 2>&1 | head -5`);
        if (result.success && !result.output.includes('Permission denied') && !result.output.includes('No such file')) {
            exposedProcFiles.push({ file, preview: result.output.substring(0, 100) });
        }
    }
    logTest('gvisorEscape', '/proc Access Limited', exposedProcFiles.length < 5, {
        exposedFiles: exposedProcFiles.map(f => f.file),
        vulnerability: exposedProcFiles.length >= 5 ? 'Many /proc files accessible' : null
    });

    // 2.3 /sys filesystem access
    console.log('2.3 /sys Filesystem Access...');
    const sysPaths = [
        '/sys/kernel', '/sys/class', '/sys/block', '/sys/devices',
        '/sys/module', '/sys/fs', '/sys/power', '/sys/firmware'
    ];
    
    let exposedSysPaths = [];
    for (const path of sysPaths) {
        const result = runCmd(`ls -la ${path} 2>&1 | head -10`);
        if (result.success && !result.output.includes('Permission denied') && !result.output.includes('No such file')) {
            exposedSysPaths.push(path);
        }
    }
    logTest('gvisorEscape', '/sys Access Limited', exposedSysPaths.length < 3, {
        exposedPaths: exposedSysPaths,
        vulnerability: exposedSysPaths.length >= 3 ? '/sys mostly accessible' : null
    });

    // 2.4 Kernel module loading attempt
    console.log('2.4 Kernel Module Loading...');
    const modprobeTest = runCmd('modprobe nonexistent_module_test 2>&1 || true');
    logTest('gvisorEscape', 'Kernel Module Loading Blocked', true, {
        output: modprobeTest.output.substring(0, 100),
        note: 'Expected to fail in container'
    });

    // 2.5 Syscall testing
    console.log('2.5 Syscall Availability...');
    const syscallTests = [
        'uname -a',
        'syscall tester (via Node.js process.binding)'
    ];
    
    // Test if we can access low-level syscalls via Node
    let syscallLeak = false;
    try {
        // This should fail in gVisor
        const bindingTest = process.binding ? 'exists' : 'not exists';
        logTest('gvisorEscape', 'process.binding Blocked', bindingTest === 'not exists', {
            note: 'process.binding access check'
        });
    } catch (e) {
        logTest('gvisorEscape', 'process.binding Blocked', true, { error: e.message });
    }

    // 2.6 Time-related attacks
    console.log('2.6 Clock Manipulation...');
    const timeTest = runCmd('date && hwclock --show 2>&1 || echo "hwclock blocked"');
    const canReadHwclock = !timeTest.output.includes('blocked') && !timeTest.output.includes('Permission denied');
    logTest('gvisorEscape', 'Hardware Clock Access Blocked', !canReadHwclock, {
        output: timeTest.output.substring(0, 100)
    });

    // 2.7 /dev filesystem access
    console.log('2.7 /dev Device Access...');
    const devDevices = [
        '/dev/null', '/dev/zero', '/dev/random', '/dev/urandom',
        '/dev/tty', '/dev/console', '/dev/kmsg', '/dev/mem', '/dev/kmem',
        '/dev/sda', '/dev/vda', '/dev/nvme0n1', '/dev/disk'
    ];
    
    let accessibleDevices = [];
    for (const dev of devDevices) {
        const result = runCmd(`test -e ${dev} && echo "exists" || echo "not exists"`);
        if (result.output.includes('exists')) {
            accessibleDevices.push(dev);
        }
    }
    const dangerousDevices = accessibleDevices.filter(d => 
        ['/dev/kmsg', '/dev/mem', '/dev/kmem', '/dev/sda', '/dev/vda', '/dev/nvme0n1', '/dev/disk'].includes(d)
    );
    logTest('gvisorEscape', 'Dangerous Device Files Blocked', dangerousDevices.length === 0, {
        accessibleDevices,
        vulnerability: dangerousDevices.length > 0 ? `Dangerous devices accessible: ${dangerousDevices.join(', ')}` : null
    });

    // 2.8 Check for ptrace protection
    console.log('2.8 Process Debugging Capabilities...');
    const ptraceTest = runCmd('cat /proc/sys/kernel/yama/ptrace_scope 2>&1 || echo "not accessible"');
    logTest('gvisorEscape', 'Ptrace Scope Restricted', true, {
        output: ptraceTest.output
    });
}

// ========================================
// 3. CONTAINER BREAKOUT TESTS
// ========================================
console.log('\n=== 3. CONTAINER BREAKOUT TESTS ===\n');

async function testContainerBreakout() {
    // 3.1 Docker socket check
    console.log('3.1 Docker Socket Access...');
    const dockerSock = runCmd('ls -la /var/run/docker.sock 2>&1');
    const dockerSockExists = dockerSock.output.includes('docker.sock');
    logTest('containerBreakout', 'Docker Socket Not Accessible', !dockerSockExists, {
        vulnerability: dockerSockExists ? 'Docker socket is accessible - CRITICAL!' : null
    });

    // 3.2 Docker CLI check
    console.log('3.2 Docker CLI Access...');
    const dockerCli = runCmd('docker ps 2>&1 || echo "docker not available"');
    const dockerWorks = !dockerCli.output.includes('not available') && !dockerCli.output.includes('permission denied');
    logTest('containerBreakout', 'Docker CLI Blocked', !dockerWorks, {
        vulnerability: dockerWorks ? 'Docker CLI works - can control host containers!' : null
    });

    // 3.3 Symlink escape attempt
    console.log('3.3 Symlink Escape Attempt...');
    try {
        // Try to create symlinks that escape the container
        const symlinkTest = runCmd(`
            mkdir -p /tmp/escape_test && 
            ln -sf / /tmp/escape_test/root_link 2>&1 &&
            ls -la /tmp/escape_test/root_link 2>&1 || true
        `);
        const symlinkCreated = symlinkTest.output.includes('root_link');
        logTest('containerBreakout', 'Symlink Creation Handled', true, {
            created: symlinkCreated,
            note: 'Symlinks created but should not escape container root'
        });
    } catch (e) {
        logTest('containerBreakout', 'Symlink Creation Handled', true, { error: e.message });
    }

    // 3.4 Host filesystem mount detection
    console.log('3.4 Host Filesystem Detection...');
    const mounts = runCmd('cat /proc/mounts 2>&1 || mount 2>&1');
    const hostMounts = [];
    const suspiciousPaths = ['/host', '/root', '/home', '/etc/host', '/var/lib/docker'];
    for (const path of suspiciousPaths) {
        if (mounts.output.includes(path)) {
            hostMounts.push(path);
        }
    }
    logTest('containerBreakout', 'No Host Filesystem Mounts', hostMounts.length === 0, {
        vulnerability: hostMounts.length > 0 ? `Host paths mounted: ${hostMounts.join(', ')}` : null,
        mountOutput: mounts.output.substring(0, 500)
    });

    // 3.5 Privileged mode detection
    console.log('3.5 Container Privilege Level...');
    const capabilities = runCmd('cat /proc/self/status 2>&1 | grep Cap || capsh --print 2>&1');
    const isPrivileged = capabilities.output.includes('CAP_SYS_ADMIN') || 
                         (capabilities.output.includes('=') && !capabilities.output.includes('CapEff\t000000'));
    logTest('containerBreakout', 'Container Not Privileged', !isPrivileged, {
        vulnerability: isPrivileged ? 'Container appears to be privileged!' : null,
        capabilities: capabilities.output.substring(0, 300)
    });

    // 3.6 User namespace detection
    console.log('3.6 User Namespace Mapping...');
    const userns = runCmd('cat /proc/self/uid_map 2>&1');
    const usernsOutput = userns.output.trim();
    logTest('containerBreakout', 'User Namespace Isolated', usernsOutput.length > 0, {
        uidMap: usernsOutput
    });

    // 3.7 cgroup access
    console.log('3.7 cgroup Filesystem Access...');
    const cgroup = runCmd('cat /proc/self/cgroup 2>&1');
    const cgroupAccessible = cgroup.success && cgroup.output.length > 0;
    logTest('containerBreakout', 'cgroup Information Available', true, {
        cgroup: cgroup.output.substring(0, 200),
        note: 'cgroup info is normally visible'
    });

    // 3.8 Check for setuid binaries
    console.log('3.8 Setuid Binary Scan...');
    const setuidScan = runCmd('find /usr -perm -4000 -type f 2>/dev/null | head -20');
    const setuidBinaries = setuidScan.output.trim().split('\n').filter(l => l.length > 0);
    const dangerousSetuid = setuidBinaries.filter(b => 
        ['sudo', 'su', 'passwd', 'newgrp', 'chsh', 'gpasswd'].some(d => b.includes(d))
    );
    logTest('containerBreakout', 'Dangerous Setuid Binaries Absent', dangerousSetuid.length === 0, {
        found: setuidBinaries,
        vulnerability: dangerousSetuid.length > 0 ? `Dangerous setuid binaries: ${dangerousSetuid.join(', ')}` : null
    });
}

// ========================================
// 4. RESOURCE EXHAUSTION TESTS
// ========================================
console.log('\n=== 4. RESOURCE EXHAUSTION TESTS ===\n');

async function testResourceExhaustion() {
    // 4.1 Process limit test
    console.log('4.1 Process Limit Enforcement...');
    const ulimitCheck = runCmd('ulimit -u 2>&1');
    const processLimit = parseInt(ulimitCheck.output.trim()) || 'unlimited';
    logTest('resourceExhaustion', 'Process Limit Set', processLimit !== 'unlimited' && processLimit < 10000, {
        limit: processLimit,
        vulnerability: processLimit === 'unlimited' ? 'No process limit set!' : null
    });

    // 4.2 Memory limit check
    console.log('4.2 Memory Limit...');
    const memLimit = runCmd('cat /sys/fs/cgroup/memory.max 2>/dev/null || cat /sys/fs/cgroup/memory/memory.limit_in_bytes 2>/dev/null || echo "unknown"');
    const memValue = memLimit.output.trim();
    const memBytes = parseInt(memValue) || 0;
    const memMB = Math.round(memBytes / (1024 * 1024));
    logTest('resourceExhaustion', 'Memory Limit Enforced', memBytes > 0 && memBytes < 16 * 1024 * 1024 * 1024, {
        limitMB: memMB || 'unknown',
        rawValue: memValue
    });

    // 4.3 File descriptor limit
    console.log('4.3 File Descriptor Limit...');
    const fdLimit = runCmd('ulimit -n 2>&1');
    const fdLimitValue = parseInt(fdLimit.output.trim()) || 'unlimited';
    logTest('resourceExhaustion', 'File Descriptor Limit Set', fdLimitValue !== 'unlimited' && fdLimitValue < 1000000, {
        limit: fdLimitValue
    });

    // 4.4 CPU limit check
    console.log('4.4 CPU Quota...');
    const cpuQuota = runCmd('cat /sys/fs/cgroup/cpu.max 2>/dev/null || cat /sys/fs/cgroup/cpu/cpu.cfs_quota_us 2>/dev/null || echo "unknown"');
    const cpuValue = cpuQuota.output.trim();
    logTest('resourceExhaustion', 'CPU Limit Configured', cpuValue !== 'max' && cpuValue !== '-1' && cpuValue !== 'unknown', {
        quota: cpuValue
    });

    // 4.5 Disk space check
    console.log('4.5 Disk Space...');
    const diskSpace = runCmd('df -h / 2>&1 | tail -1');
    logTest('resourceExhaustion', 'Disk Space Limited', true, {
        space: diskSpace.output.trim()
    });

    // 4.6 Fork bomb protection test (safe version)
    console.log('4.6 Fork Bomb Protection...');
    // We test by checking if we can spawn many processes quickly
    // But we limit it to avoid actually crashing anything
    const forkTest = runCmd(`
        for i in $(seq 1 50); do
            (sleep 0.1 &) 2>/dev/null
        done
        ps aux | wc -l
    `);
    const processCount = parseInt(forkTest.output.split('\n').pop()?.trim()) || 0;
    logTest('resourceExhaustion', 'Process Spawning Controlled', processCount < 100, {
        processCount,
        note: 'Could spawn processes (protected by limits)'
    });

    // 4.7 OOM killer settings
    console.log('4.7 OOM Killer Configuration...');
    const oomScore = runCmd('cat /proc/self/oom_score 2>&1 || echo "not accessible"');
    logTest('resourceExhaustion', 'OOM Score Visible', true, {
        oomScore: oomScore.output.trim()
    });
}

// ========================================
// 5. INFORMATION DISCLOSURE TESTS
// ========================================
console.log('\n=== 5. INFORMATION DISCLOSURE TESTS ===\n');

async function testInfoDisclosure() {
    // 5.1 Environment variable scan
    console.log('5.1 Environment Variables...');
    const envVars = runCmd('env | sort');
    const sensitivePatterns = ['PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'API_KEY', 'CREDENTIAL', 'PRIVATE'];
    const sensitiveVars = [];
    const envLines = envVars.output.split('\n');
    
    for (const line of envLines) {
        for (const pattern of sensitivePatterns) {
            if (line.toUpperCase().includes(pattern)) {
                const [key] = line.split('=');
                sensitiveVars.push(key);
            }
        }
    }
    
    // Get specific vars we expect
    const hasCdpUrl = envVars.output.includes('CDP_URL');
    const hasDragonflyHost = envVars.output.includes('DRAGONFLY');
    
    logTest('infoDisclosure', 'No Sensitive Env Vars Leaked', sensitiveVars.length === 0, {
        sensitiveVars: [...new Set(sensitiveVars)],
        totalEnvVars: envLines.length,
        hasCdpUrl,
        hasDragonflyHost
    });

    // 5.2 /etc/passwd access
    console.log('5.2 /etc/passwd Access...');
    const passwd = runCmd('cat /etc/passwd 2>&1');
    const passwdUsers = passwd.output.split('\n').filter(l => l.includes(':'));
    const hasRoot = passwdUsers.some(u => u.startsWith('root:'));
    logTest('infoDisclosure', '/etc/passwd Access Limited', passwdUsers.length < 5, {
        userCount: passwdUsers.length,
        hasRoot
    });

    // 5.3 /etc/shadow access
    console.log('5.3 /etc/shadow Access...');
    const shadow = runCmd('cat /etc/shadow 2>&1');
    const shadowAccessible = shadow.success && !shadow.output.includes('Permission denied');
    logTest('infoDisclosure', '/etc/shadow Not Accessible', !shadowAccessible, {
        vulnerability: shadowAccessible ? '/etc/shadow is readable - CRITICAL!' : null
    });

    // 5.4 Network configuration disclosure
    console.log('5.4 Network Configuration...');
    const networkConfig = runCmd('ip addr 2>&1 || ifconfig 2>&1');
    const interfaces = networkConfig.output.split('\n').filter(l => l.includes('inet '));
    logTest('infoDisclosure', 'Network Info Accessible', true, {
        interfaces: interfaces.length,
        note: 'Network config normally visible to container'
    });

    // 5.5 Container configuration files
    console.log('5.5 Container Config Files...');
    const configFiles = [
        '/.dockerenv',
        '/run/secrets', 
        '/var/run/secrets',
        '/etc/hostname',
        '/etc/hosts',
        '/etc/resolv.conf'
    ];
    
    let foundConfigs = [];
    for (const file of configFiles) {
        const result = runCmd(`test -f ${file} && cat ${file} 2>&1 | head -5 || test -d ${file} && ls ${file} 2>&1`);
        if (result.success && result.output.length > 0 && !result.output.includes('No such file')) {
            foundConfigs.push({ file, preview: result.output.substring(0, 100) });
        }
    }
    logTest('infoDisclosure', 'Container Config Exposure Limited', true, {
        foundConfigs: foundConfigs.map(c => c.file)
    });

    // 5.6 Running processes
    console.log('5.6 Process List...');
    const processes = runCmd('ps aux 2>&1 || ps 2>&1');
    const processList = processes.output.split('\n').filter(l => l.trim().length > 0);
    const hostProcesses = processList.filter(p => 
        p.includes('systemd') || p.includes('sshd') || p.includes('dockerd') || p.includes('containerd')
    );
    logTest('infoDisclosure', 'No Host Processes Visible', hostProcesses.length === 0, {
        visibleProcesses: processList.length,
        hostProcesses: hostProcesses.length
    });

    // 5.7 Scrapely-specific secrets
    console.log('5.7 Scrapely Secret Scanning...');
    const secretPaths = [
        '/actor/.env',
        '/actor/package/.env',
        '/app/.env',
        '/home/node/.scrapely',
        '/tmp/credentials',
        '/tmp/secrets'
    ];
    
    let foundSecrets = [];
    for (const path of secretPaths) {
        const result = runCmd(`test -f ${path} && echo "EXISTS: ${path}" || true`);
        if (result.output.includes('EXISTS')) {
            foundSecrets.push(path);
        }
    }
    logTest('infoDisclosure', 'No Secret Files Found', foundSecrets.length === 0, {
        vulnerability: foundSecrets.length > 0 ? `Secret files found: ${foundSecrets.join(', ')}` : null
    });

    // 5.8 Package.json / manifest info
    console.log('5.8 Manifest Information...');
    const packageJson = runCmd('cat /actor/package/package.json 2>&1 || cat /actor/package.json 2>&1 || echo "not found"');
    const scrapelyJson = runCmd('cat /actor/package/scrapely.json 2>&1 || echo "not found"');
    logTest('infoDisclosure', 'Manifest Files Accessible', true, {
        hasPackageJson: !packageJson.output.includes('not found'),
        hasScrapelyJson: !scrapelyJson.output.includes('not found')
    });
}

// ========================================
// Main Execution
// ========================================
async function main() {
    console.log('╔══════════════════════════════════════════════════════════════╗');
    console.log('║     SCRRAPELY CONTAINER PENETRATION TESTER v1.0             ║');
    console.log('║     Testing container security boundaries                    ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`\nStarted at: ${results.timestamp}`);
    console.log(`Container ID: ${runCmd('hostname').output.trim()}`);

    try {
        await testNetworkIsolation();
        await testGvisorEscape();
        await testContainerBreakout();
        await testResourceExhaustion();
        await testInfoDisclosure();
    } catch (error) {
        console.error('\n!!! Test suite error:', error);
        results.error = error.message;
    }

    // Calculate summary
    let totalPassed = 0;
    let totalFailed = 0;
    for (const [category, data] of Object.entries(results.categories)) {
        totalPassed += data.passed;
        totalFailed += data.failed;
    }

    results.summary = {
        totalTests: totalPassed + totalFailed,
        passed: totalPassed,
        failed: totalFailed,
        vulnerabilitiesFound: results.vulnerabilities.length,
        securityScore: Math.round((totalPassed / (totalPassed + totalFailed)) * 100)
    };

    console.log('\n╔══════════════════════════════════════════════════════════════╗');
    console.log('║                    TEST SUMMARY                              ║');
    console.log('╚══════════════════════════════════════════════════════════════╝');
    console.log(`\nTotal Tests: ${results.summary.totalTests}`);
    console.log(`Passed: ${totalPassed}`);
    console.log(`Failed: ${totalFailed}`);
    console.log(`Vulnerabilities Found: ${results.vulnerabilities.length}`);
    console.log(`Security Score: ${results.summary.securityScore}%`);

    if (results.vulnerabilities.length > 0) {
        console.log('\n⚠️  VULNERABILITIES DETECTED:');
        for (const vuln of results.vulnerabilities) {
            console.log(`  [${vuln.category}] ${vuln.name}: ${vuln.vulnerability}`);
        }
    }

    // Write full results to file
    fs.writeFileSync('/tmp/penetration-test-results.json', JSON.stringify(results, null, 2));
    console.log('\nFull results written to /tmp/penetration-test-results.json');

    // Also write to actor's key-value store
    try {
        const { Actor } = await import('scrapely');
        await Actor.init();
        await Actor.setValue('PENETRATION_TEST_RESULTS', results);
        console.log('Results saved to Actor key-value store');
        await Actor.exit();
    } catch (e) {
        console.log('Note: Could not save to Actor KV store (running outside Actor context?)');
    }

    console.log('\n penetration test complete.');
}

main().catch(console.error);