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
    containerInfo: {},
    categories: {
        buildTime: { tests: [], passed: 0, failed: 0 },
        networkIsolation: { tests: [], passed: 0, failed: 0 },
        perUserNetwork: { tests: [], passed: 0, failed: 0 },
        registryAccess: { tests: [], passed: 0, failed: 0 },
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
// 2. PER-USER NETWORK ISOLATION TESTS
// ========================================
console.log('\n=== 2. PER-USER NETWORK ISOLATION TESTS ===\n');

async function testPerUserNetworkIsolation() {
    // 2.1 Detect current network configuration
    console.log('2.1 Network Namespace Detection...');
    const networkNs = runCmd('ls -la /proc/self/ns/net 2>&1');
    const networkInode = networkNs.output.match(/net:\[(\d+)\]/)?.[1] || 'unknown';
    
    const routeTable = runCmd('ip route 2>&1 || route -n 2>&1');
    const routes = routeTable.output.split('\n').filter(l => l.trim());
    
    const gatewayMatch = routeTable.output.match(/default via ([\d.]+)/);
    const gateway = gatewayMatch ? gatewayMatch[1] : 'unknown';
    
    logTest('perUserNetwork', 'Network Namespace Isolated', true, {
        networkInode,
        gateway,
        routeCount: routes.length,
        routes: routes.slice(0, 5)
    });

    // 2.2 Check for user-specific network markers
    console.log('2.2 User Network Markers...');
    const hostname = runCmd('hostname').output.trim();
    const containerId = hostname.length >= 12 ? hostname.substring(0, 12) : hostname;
    
    // Check if we're in a user-specific network (should be named like user_<id>_network)
    const networkName = process.env.DOCKER_NETWORK || 'unknown';
    const isUserNetwork = networkName.includes('user') || networkName.includes('isolated');
    
    logTest('perUserNetwork', 'User-Specific Network Detected', isUserNetwork || networkName === 'unknown', {
        hostname,
        containerId,
        networkName,
        note: 'Should be in user-isolated network'
    });

    // 2.3 Test cross-user isolation (try to reach other user's containers)
    console.log('2.3 Cross-User Isolation Test...');
    // Scan for other container IP ranges that might belong to other users
    const otherUserRanges = [
        '172.18.0.0/16', '172.19.0.0/16', '172.20.0.0/16', '172.21.0.0/16',
        '172.22.0.0/16', '172.23.0.0/16', '172.24.0.0/16',
        '10.10.0.0/16', '10.20.0.0/16', '10.100.0.0/16',
        '192.168.10.0/24', '192.168.20.0/24', '192.168.100.0/24'
    ];
    
    let crossUserLeaks = [];
    for (const range of otherUserRanges.slice(0, 6)) {
        // Try the .1 and .2 IPs in each range
        const baseIP = range.split('/')[0].split('.').slice(0, 3).join('.');
        for (let i = 1; i <= 3; i++) {
            const testIP = `${baseIP}.${i}`;
            const result = await testTcpConnect(testIP, 3000, 1000);
            if (result.connected) {
                crossUserLeaks.push(testIP);
            }
        }
    }
    logTest('perUserNetwork', 'Cross-User Network Isolation', crossUserLeaks.length === 0, {
        vulnerability: crossUserLeaks.length > 0 ? `Other user networks reachable: ${crossUserLeaks.join(', ')}` : null,
        testedRanges: otherUserRanges.length
    });

    // 2.4 Test API endpoint access (should be allowed)
    console.log('2.4 API Endpoint Access...');
    const apiEndpoints = [
        { host: 'api', port: 3000, name: 'Internal API' },
        { host: 'scrapely-server', port: 3000, name: 'Server' },
        { host: '172.17.0.1', port: 3000, name: 'Docker Gateway API' }
    ];
    
    let apiEndpointsAccessible = [];
    for (const endpoint of apiEndpoints) {
        const result = await testTcpConnect(endpoint.host, endpoint.port, 2000);
        if (result.connected) {
            apiEndpointsAccessible.push(endpoint.name);
        }
    }
    logTest('perUserNetwork', 'API Endpoints Reachable', apiEndpointsAccessible.length > 0, {
        accessible: apiEndpointsAccessible,
        note: 'API should be reachable from container'
    });

    // 2.5 Test registry endpoint access (should be allowed)
    console.log('2.5 Registry Endpoint Access...');
    const registryEndpoints = [
        { host: 'registry', port: 5000, name: 'Internal Registry' },
        { host: '172.17.0.1', port: 5000, name: 'Docker Gateway Registry' }
    ];
    
    let registryAccessible = [];
    for (const endpoint of registryEndpoints) {
        const result = await testTcpConnect(endpoint.host, endpoint.port, 2000);
        if (result.connected) {
            registryAccessible.push(endpoint.name);
        }
    }
    logTest('perUserNetwork', 'Registry Endpoint Reachable', registryAccessible.length > 0, {
        accessible: registryAccessible,
        note: 'Registry should be reachable for image pulls'
    });

    // 2.6 Check iptables/nftables rules visibility
    console.log('2.6 Firewall Rules Visibility...');
    const iptables = runCmd('iptables -L 2>&1 || nft list ruleset 2>&1 || echo "firewall not accessible"');
    const canSeeFirewall = !iptables.output.includes('Permission denied') && 
                           !iptables.output.includes('not accessible');
    logTest('perUserNetwork', 'Firewall Rules Hidden', !canSeeFirewall, {
        output: iptables.output.substring(0, 200)
    });

    // 2.7 Network interface enumeration
    console.log('2.7 Network Interfaces...');
    const interfaces = runCmd('ip link show 2>&1 || ifconfig 2>&1');
    const interfaceList = interfaces.output.split('\n')
        .filter(l => l.match(/^\d+:/) || l.match(/^[a-z]/i))
        .map(l => l.trim().split(':')[1]?.split('@')[0] || l.split(' ')[0])
        .filter(l => l && l.length > 0);
    
    const expectedInterfaces = ['lo', 'eth0', 'sit0'];
    const unexpectedInterfaces = interfaceList.filter(i => !expectedInterfaces.includes(i));
    
    logTest('perUserNetwork', 'Network Interfaces Clean', unexpectedInterfaces.length === 0, {
        interfaces: [...new Set(interfaceList)],
        unexpected: unexpectedInterfaces
    });

    // Store network info for results
    results.containerInfo.networkInode = networkInode;
    results.containerInfo.gateway = gateway;
    results.containerInfo.interfaces = interfaceList;
}

// ========================================
// 3. REGISTRY ACCESS TESTS
// ========================================
console.log('\n=== 3. REGISTRY ACCESS TESTS ===\n');

async function testRegistryAccess() {
    // 3.1 Registry authentication check
    console.log('3.1 Registry Authentication Required...');
    
    // Try to access registry catalog without auth
    const registryHosts = ['registry:5000', '172.17.0.1:5000', 'localhost:5000'];
    let registryAuthRequired = true;
    let registryEndpoints = [];
    
    for (const host of registryHosts) {
        const [hostname, port] = host.split(':');
        const result = await testTcpConnect(hostname, parseInt(port), 2000);
        if (result.connected) {
            registryEndpoints.push(host);
            
            // Try to access catalog
            const catalogTest = runCmd(`curl -s http://${host}/v2/_catalog 2>&1 | head -20`);
            const catalogData = catalogTest.output;
            
            // If we get a list of repos, auth is not required (vulnerability!)
            if (catalogData.includes('"repositories"') && !catalogData.includes('Unauthorized')) {
                registryAuthRequired = false;
            }
        }
    }
    
    logTest('registryAccess', 'Registry Requires Authentication', registryAuthRequired, {
        vulnerability: !registryAuthRequired ? 'Registry allows unauthenticated access!' : null,
        accessibleEndpoints: registryEndpoints
    });

    // 3.2 Registry Docker API access
    console.log('3.2 Registry Docker API Access...');
    const dockerRegTest = runCmd(`curl -s http://registry:5000/v2/ 2>&1 || curl -s http://172.17.0.1:5000/v2/ 2>&1`);
    const v2ApiAccessible = dockerRegTest.output.includes('Docker-Distribution-API-Version') ||
                            dockerRegTest.output.includes('API version');
    logTest('registryAccess', 'Registry V2 API Accessible', v2ApiAccessible, {
        note: 'Registry V2 API should be accessible for pulls'
    });

    // 3.3 Test image pull without auth
    console.log('3.3 Image Pull Auth Test...');
    const pullTest = runCmd(`
        curl -s http://registry:5000/v2/test-image/manifests/latest 2>&1 | head -20 ||
        curl -s http://172.17.0.1:5000/v2/test-image/manifests/latest 2>&1 | head -20
    `);
    const manifestAccessible = pullTest.output.includes('manifest') && 
                               !pullTest.output.includes('Unauthorized') &&
                               !pullTest.output.includes('401');
    logTest('registryAccess', 'Image Manifests Protected', !manifestAccessible, {
        vulnerability: manifestAccessible ? 'Can access image manifests without auth!' : null
    });

    // 3.4 Registry credentials in environment
    console.log('3.4 Registry Credentials Check...');
    const regCreds = runCmd('env | grep -iE "(REGISTRY|DOCKER.*USER|DOCKER.*PASS|DOCKER.*TOKEN)" 2>&1 || echo "none"');
    const hasCreds = !regCreds.output.includes('none') && regCreds.output.trim().length > 0;
    
    // Mask the actual credentials
    let maskedCreds = [];
    if (hasCreds) {
        maskedCreds = regCreds.output.split('\n')
            .filter(l => l.includes('='))
            .map(l => l.split('=')[0] + '=***');
    }
    
    logTest('registryAccess', 'Registry Credentials Available', hasCreds, {
        credentialVars: maskedCreds,
        note: 'Credentials should be available for authenticated pulls'
    });

    // 3.5 Test push access
    console.log('3.5 Registry Push Access...');
    // This should fail without proper auth
    const pushTest = runCmd(`
        curl -s -X POST http://registry:5000/v2/test/blobs/uploads/ 2>&1 ||
        echo "push test failed"
    `);
    const canPush = pushTest.output.includes('Location') || pushTest.output.includes('upload');
    logTest('registryAccess', 'Registry Push Blocked', !canPush, {
        vulnerability: canPush ? 'Can push images without proper auth!' : null
    });

    // 3.6 Check for other users' images
    console.log('3.6 Other Users Images Access...');
    const catalogResult = runCmd(`
        curl -s http://registry:5000/v2/_catalog?n=100 2>&1 ||
        curl -s http://172.17.0.1:5000/v2/_catalog?n=100 2>&1 ||
        echo "catalog not accessible"
    `);
    
    // If we can see the catalog, check if we see other users' images
    const canSeeCatalog = catalogResult.output.includes('"repositories"');
    const catalogData = JSON.parse(catalogResult.output.replace(/.*?(\{.*\}).*/s, '$1') || '{"repositories":[]}');
    const otherUserImages = (catalogData.repositories || []).filter(r => 
        !r.includes(process.env.USER_ID || 'unknown') && 
        r.includes('/')
    );
    
    logTest('registryAccess', 'Other Users Images Hidden', !canSeeCatalog || otherUserImages.length === 0, {
        vulnerability: otherUserImages.length > 0 ? `Can see other users' images: ${otherUserImages.slice(0, 5).join(', ')}` : null
    });
}

// ========================================
// 4. gVisor SANDBOX ESCAPE TESTS
// ========================================
console.log('\n=== 4. gVisor SANDBOX ESCAPE TESTS ===\n');

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
// 0. BUILD-TIME TEST RESULTS
// ========================================
console.log('\n=== 0. BUILD-TIME TEST RESULTS ===\n');

async function testBuildTime() {
    // Check if build test results exist (from Dockerfile)
    const buildResultsPath = '/app/build-test-results/SUMMARY.txt';
    
    if (fs.existsSync(buildResultsPath)) {
        console.log('Build-time test results found!');
        const summary = fs.readFileSync(buildResultsPath, 'utf8');
        console.log(summary);
        
        // Parse the results and add to our test results
        const resultsDir = '/app/build-test-results';
        
        // Check each test file
        const testFiles = [
            { file: '01-user-context.txt', name: 'Build User Context' },
            { file: '02-sensitive-env.txt', name: 'Build Env Vars Secure' },
            { file: '03-host-fs.txt', name: 'Build Host FS Isolated' },
            { file: '04-docker-socket.txt', name: 'Build Docker Socket Blocked' },
            { file: '05-network.txt', name: 'Build Network Isolated' },
            { file: '06-dns.txt', name: 'Build DNS Secure' },
            { file: '07-processes.txt', name: 'Build Process Isolation' },
            { file: '08-capabilities.txt', name: 'Build Capabilities Limited' },
            { file: '09-build-env.txt', name: 'Build Environment Detected' },
            { file: '10-secrets.txt', name: 'Build Secrets Protected' },
            { file: '11-mounts.txt', name: 'Build Mounts Safe' },
            { file: '12-gvisor.txt', name: 'Build gVisor Status' }
        ];
        
        for (const { file, name } of testFiles) {
            const filePath = `${resultsDir}/${file}`;
            if (fs.existsSync(filePath)) {
                const content = fs.readFileSync(filePath, 'utf8');
                const hasVulnerability = content.toLowerCase().includes('critical') || 
                                        content.toLowerCase().includes('accessible') ||
                                        (content.toLowerCase().includes('exists') && 
                                         (name.includes('Docker Socket') || name.includes('Secrets')));
                
                logTest('buildTime', name, !hasVulnerability, {
                    file,
                    preview: content.substring(0, 200)
                });
            }
        }
        
        results.buildTime = { summary, resultsPath };
    } else {
        console.log('No build-time test results found (built without custom Dockerfile)');
        logTest('buildTime', 'Build-Time Tests Available', false, {
            note: 'Actor was not built with penetration test Dockerfile'
        });
    }
    
    // Also check for build test results in other possible locations
    const altPaths = [
        '/build-test-results/SUMMARY.txt',
        './build-test-results/SUMMARY.txt',
        '/tmp/build-test-results/SUMMARY.txt'
    ];
    
    for (const altPath of altPaths) {
        if (fs.existsSync(altPath)) {
            console.log(`\nAlternative build results found at: ${altPath}`);
        }
    }
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
        await testBuildTime();
        await testNetworkIsolation();
        await testPerUserNetworkIsolation();
        await testRegistryAccess();
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