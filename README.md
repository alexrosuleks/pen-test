# Scrapely Container Penetration Tester (v2)

A comprehensive security testing actor that validates container isolation, network security, and access controls in the Scrapely platform.

## What It Tests

### 0. Container Hardening (runtime)
- `CapEff` zero (`CapDrop: ALL` on run containers)
- `NoNewPrivs=1` (`no-new-privileges`)
- Not privileged / no privileged mounts

### 0b. Scrapely platform env
- Forbidden secrets absent (`ADMIN_API_KEY`, `SINGLESTORE_*`, `REGISTRY_PASSWORD`, etc.)
- Expected run env present (`SCRAPELY_TOKEN`, `SCRAPELY_API_URL`, `CDP_URL`, …)
- `SCRAPELY_API_URL` reachable
- No `DOCKER_HOST` in container

### 1. Build-Time Security Tests
Tests performed during Docker image build:
- User context and privileges
- Sensitive environment variable exposure
- Host filesystem access attempts
- Docker socket accessibility
- Network access during build
- DNS resolution capabilities
- Process visibility
- Container capabilities
- Build environment detection (Kaniko, etc.)
- Secret file exposure
- Mounted volume detection
- gVisor/runtime detection

### 2. Network Isolation Tests
- IPv6 bypass attempts
- Internal IP + **database ports** blocked (not mis-flagging API :3000)
- Cloud metadata `169.254.169.254` blocked
- SSH to docker gateway blocked
- `resolv.conf` public DNS (gVisor)
- Compose service name DNS should not resolve
- Internet egress available

### 3. Per-User Network Isolation Tests
- Container IP in `172.32–47.x` user subnets
- Cross-user gateway scan (`172.32.0.1` … `172.47.0.1` on DB ports)
- Host firewall rules not visible from container

### 4. Registry Access Tests
- Registry authentication requirements
- Registry V2 API access
- Image manifest access without auth
- Registry credentials in environment
- Push access restrictions
- Other users' image visibility

### 5. gVisor Sandbox Escape Tests
- gVisor runtime detection
- /proc filesystem access
- /sys filesystem access
- Kernel module loading attempts
- Syscall availability
- Hardware clock access
- Dangerous device file access (/dev/mem, /dev/kmsg, etc.)
- Process debugging capabilities

### 6. Container Breakout Tests
- Docker socket access
- Docker CLI availability
- Symlink escape attempts
- Host filesystem mount detection
- Privileged mode detection
- User namespace isolation
- cgroup access
- Setuid binary scanning

### 7. Resource Exhaustion Tests
- Process limits
- Memory limits
- File descriptor limits
- CPU quotas
- Disk space limits
- Fork bomb protection
- OOM killer configuration

### 8. Information Disclosure Tests
- Platform secrets must not appear in env (user `SCRAPELY_TOKEN` is expected)
- No host daemon processes visible
- No readable `/kaniko/.docker/config.json` or platform `.env` files

## Usage

### Run via Scrapely Platform
1. Build and deploy this actor to your Scrapely instance
2. Run the actor with default input
3. Check the key-value store for `PENETRATION_TEST_RESULTS`

### Run Locally for Testing
```bash
cd penetration-tester
npm install
node main.js
```

## Output

The actor produces a comprehensive JSON report with:

```json
{
  "timestamp": "2026-05-26T...",
  "containerInfo": {
    "networkInode": "12345",
    "gateway": "172.17.0.1",
    "interfaces": ["lo", "eth0"]
  },
  "categories": {
    "networkIsolation": { "tests": [...], "passed": 10, "failed": 0 },
    "perUserNetwork": { "tests": [...], "passed": 7, "failed": 0 },
    "registryAccess": { "tests": [...], "passed": 6, "failed": 0 },
    ...
  },
  "vulnerabilities": [],
  "summary": {
    "totalTests": 60,
    "passed": 58,
    "failed": 2,
    "vulnerabilitiesFound": 2,
    "securityScore": 97
  }
}
```

## Security Expectations

For a properly secured Scrapely deployment, the penetration tester should find:

✅ **Should PASS:**
- API endpoint reachable (port 3000)
- Registry endpoint reachable (port 5000)
- Internet access available
- External DNS resolution working
- gVisor runtime detected
- Container not privileged
- Docker socket not accessible
- No host filesystem mounts
- No sensitive env vars leaked
- Other users' networks not reachable

❌ **Should FAIL (vulnerability if found):**
- Database ports reachable
- Internal IPs accessible (except API/Registry)
- Other users' images visible
- Docker socket accessible
- /etc/shadow readable
- Privileged container capabilities

## Customization

You can modify the test behavior by:

1. Adding more internal IPs to scan in `testNetworkIsolation()`
2. Adding more registry endpoints in `testRegistryAccess()`
3. Adding more internal hostnames in `testNetworkIsolation()`
4. Modifying the security pass/fail criteria in each test function

## Files

- `main.js` - Main penetration test script
- `Dockerfile` - Build-time test container
- `package.json` - Node.js dependencies
- `scrapely.json` - Actor configuration