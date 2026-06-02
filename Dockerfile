# =============================================================================
# Scrapely Build-Time Penetration Tester
# =============================================================================
# This Dockerfile attempts various attacks during the build process to identify
# security vulnerabilities in the build environment (Kaniko, Docker, etc.)
#
# Tests performed during build:
# 1. Host filesystem access attempts
# 2. Network access during build
# 3. Secret/credential exposure
# 4. Docker socket access
# 5. Privilege escalation
# 6. Kaniko-specific tests
# =============================================================================

# Single-stage build for Kaniko compatibility
FROM node:22-slim

# Install tools needed for penetration testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    wget \
    netcat-openbsd \
    iproute2 \
    iputils-ping \
    dnsutils \
    procps \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create results directory
RUN mkdir -p /build-test-results

# =============================================================================
# BUILD-TIME PENETRATION TESTS
# =============================================================================

# Test 1: Check what user we're running as
RUN echo "=== BUILD TEST 1: User Context ===" && \
    id && \
    whoami && \
    echo "Result: $(id -u):$(id -g)" > /build-test-results/01-user-context.txt

# Test 2: Check for sensitive environment variables
RUN echo "=== BUILD TEST 2: Environment Variables ===" && \
    env | sort > /build-test-results/02-env-vars.txt && \
    echo "Checking for sensitive patterns..." && \
    env | grep -iE "(PASSWORD|SECRET|KEY|TOKEN|API_KEY|CREDENTIAL|PRIVATE)" > /build-test-results/02-sensitive-env.txt 2>&1 || true

# Test 3: Try to access host filesystem paths
RUN echo "=== BUILD TEST 3: Host Filesystem Access ===" && \
    echo "Testing common host paths..." && \
    for path in /host /root /home /var/run/docker.sock /etc/shadow /etc/passwd /proc/1; do \
        if [ -e "$path" ]; then \
            echo "ACCESSIBLE: $path" >> /build-test-results/03-host-fs.txt; \
            ls -la "$path" >> /build-test-results/03-host-fs.txt 2>&1 || true; \
        else \
            echo "NOT ACCESSIBLE: $path" >> /build-test-results/03-host-fs.txt; \
        fi; \
    done

# Test 4: Docker socket test
RUN echo "=== BUILD TEST 4: Docker Socket ===" && \
    if [ -S /var/run/docker.sock ]; then \
        echo "DOCKER SOCKET EXISTS - CRITICAL!" > /build-test-results/04-docker-socket.txt; \
        ls -la /var/run/docker.sock >> /build-test-results/04-docker-socket.txt; \
    else \
        echo "Docker socket not accessible (good)" > /build-test-results/04-docker-socket.txt; \
    fi

# Test 5: Network access during build
RUN echo "=== BUILD TEST 5: Network Access ===" && \
    echo "Testing network connectivity..." > /build-test-results/05-network.txt && \
    timeout 2 bash -c 'echo >/dev/tcp/172.17.0.1/3306' 2>/dev/null && echo "172.17.0.1:3306 - open" >> /build-test-results/05-network.txt || echo "172.17.0.1:3306 - blocked" >> /build-test-results/05-network.txt; \
    timeout 2 bash -c 'echo >/dev/tcp/172.17.0.1/6379' 2>/dev/null && echo "172.17.0.1:6379 - open" >> /build-test-results/05-network.txt || echo "172.17.0.1:6379 - blocked" >> /build-test-results/05-network.txt; \
    timeout 2 bash -c 'echo >/dev/tcp/172.17.0.1/22' 2>/dev/null && echo "172.17.0.1:22 - open" >> /build-test-results/05-network.txt || echo "172.17.0.1:22 - blocked" >> /build-test-results/05-network.txt; \
    timeout 2 bash -c 'echo >/dev/tcp/172.17.0.1/5000' 2>/dev/null && echo "172.17.0.1:5000 - open" >> /build-test-results/05-network.txt || echo "172.17.0.1:5000 - blocked" >> /build-test-results/05-network.txt; \
    timeout 2 bash -c 'echo >/dev/tcp/172.32.0.1/3306' 2>/dev/null && echo "172.32.0.1:3306 - open" >> /build-test-results/05-network.txt || echo "172.32.0.1:3306 - blocked" >> /build-test-results/05-network.txt; \
    timeout 2 bash -c 'echo >/dev/tcp/169.254.169.254/80' 2>/dev/null && echo "169.254.169.254:80 - open" >> /build-test-results/05-network.txt || echo "169.254.169.254:80 - blocked" >> /build-test-results/05-network.txt; \
    timeout 2 curl -s http://172.30.0.1:3000 >> /build-test-results/05-network.txt 2>&1 || echo "172.30.0.1:3000 - blocked or timeout" >> /build-test-results/05-network.txt; \
    timeout 2 curl -s http://10.0.0.1:3000 >> /build-test-results/05-network.txt 2>&1 || echo "10.0.0.1:3000 - blocked or timeout" >> /build-test-results/05-network.txt; \
    timeout 2 curl -sS -m 2 http://172.17.0.1:5000/v2/ >> /build-test-results/05-network.txt 2>&1 || echo "172.17.0.1:5000 http - blocked or timeout" >> /build-test-results/05-network.txt; \
    timeout 5 curl -s https://google.com >> /build-test-results/05-network.txt 2>&1 && echo "Internet accessible" >> /build-test-results/05-network.txt || echo "Internet blocked" >> /build-test-results/05-network.txt

# Test 6: DNS resolution during build
RUN echo "=== BUILD TEST 6: DNS Resolution ===" && \
    echo "Testing DNS..." > /build-test-results/06-dns.txt && \
    nslookup google.com >> /build-test-results/06-dns.txt 2>&1 || echo "External DNS failed" >> /build-test-results/06-dns.txt; \
    nslookup dragonfly >> /build-test-results/06-dns.txt 2>&1 || echo "Internal DNS (dragonfly) failed" >> /build-test-results/06-dns.txt; \
    nslookup redis >> /build-test-results/06-dns.txt 2>&1 || echo "Internal DNS (redis) failed" >> /build-test-results/06-dns.txt; \
    nslookup singlestore >> /build-test-results/06-dns.txt 2>&1 || echo "Internal DNS (singlestore) failed" >> /build-test-results/06-dns.txt

# Test 7: Process visibility
RUN echo "=== BUILD TEST 7: Process Visibility ===" && \
    ps aux > /build-test-results/07-processes.txt 2>&1 || echo "ps failed" > /build-test-results/07-processes.txt; \
    cat /proc/1/cmdline >> /build-test-results/07-processes.txt 2>&1 || echo "/proc/1 not accessible" >> /build-test-results/07-processes.txt

# Test 8: Filesystem capabilities
RUN echo "=== BUILD TEST 8: Capabilities ===" && \
    cat /proc/self/status | grep Cap > /build-test-results/08-capabilities.txt 2>&1 || echo "Could not read capabilities" > /build-test-results/08-capabilities.txt

# Test 9: Kaniko-specific test (check if we're in Kaniko)
RUN echo "=== BUILD TEST 9: Build Environment Detection ===" && \
    echo "Checking for Kaniko..." > /build-test-results/09-build-env.txt; \
    if [ -f /kaniko/executor ]; then \
        echo "KANIKO_VISIBLE_IN_RUN" >> /build-test-results/09-build-env.txt; \
        ls -la /kaniko/ >> /build-test-results/09-build-env.txt 2>&1; \
    else \
        echo "Kaniko executor not visible in RUN layer (good)" >> /build-test-results/09-build-env.txt; \
    fi; \
    echo "Container runtime: $(cat /proc/1/cgroup 2>/dev/null | head -5)" >> /build-test-results/09-build-env.txt 2>&1 || true

# Test 10: Attempt to read secrets
RUN echo "=== BUILD TEST 10: Secret Files ===" && \
    echo "Scanning for secret files..." > /build-test-results/10-secrets.txt; \
    for path in /run/secrets /var/run/secrets /etc/secrets /secrets /.docker/config.json; do \
        if [ -e "$path" ]; then \
            echo "FOUND: $path" >> /build-test-results/10-secrets.txt; \
            ls -la "$path" >> /build-test-results/10-secrets.txt 2>&1 || true; \
        fi; \
    done

# Test 11: Check for mounted volumes
RUN echo "=== BUILD TEST 11: Mounted Volumes ===" && \
    mount > /build-test-results/11-mounts.txt 2>&1 || echo "mount command failed" > /build-test-results/11-mounts.txt; \
    cat /proc/mounts >> /build-test-results/11-mounts.txt 2>&1 || true

# Test 12: gVisor detection
RUN echo "=== BUILD TEST 12: gVisor Detection ===" && \
    cat /proc/version > /build-test-results/12-gvisor.txt 2>&1 || echo "Could not read /proc/version" > /build-test-results/12-gvisor.txt; \
    dmesg 2>&1 | head -10 >> /build-test-results/12-gvisor.txt || echo "dmesg not available" >> /build-test-results/12-gvisor.txt

# Test 13: Escape probes during build
RUN echo "=== BUILD TEST 13: Escape Probes ===" > /build-test-results/13-escape.txt && \
    echo "container_hostname=$(cat /etc/hostname 2>/dev/null | tr -d '\n')" >> /build-test-results/13-escape.txt && \
    echo "proc1_root_hostname=$(cat /proc/1/root/etc/hostname 2>/dev/null | tr -d '\n')" >> /build-test-results/13-escape.txt && \
    if [ "$(cat /etc/hostname 2>/dev/null | tr -d '\n')" = "$(cat /proc/1/root/etc/hostname 2>/dev/null | tr -d '\n')" ]; then \
        echo "proc1_hostname_matches_container" >> /build-test-results/13-escape.txt; \
    else \
        echo "proc1_hostname_mismatch" >> /build-test-results/13-escape.txt; \
    fi && \
    mkdir -p /tmp/build-mnt && \
    mount -t tmpfs tmpfs /tmp/build-mnt 2>&1 >> /build-test-results/13-escape.txt || echo "mount blocked" >> /build-test-results/13-escape.txt; \
    curl -sS -m 3 http://169.254.169.254/latest/meta-data/ >> /build-test-results/13-escape.txt 2>&1 || echo "metadata HTTP blocked" >> /build-test-results/13-escape.txt

# Test 14: SSRF HTTP during build
RUN echo "=== BUILD TEST 14: SSRF HTTP ===" > /build-test-results/14-ssrf.txt && \
    curl -sS -m 3 http://127.0.0.1:3000/health >> /build-test-results/14-ssrf.txt 2>&1 || echo "127.0.0.1 blocked" >> /build-test-results/14-ssrf.txt; \
    curl -sS -m 3 file:///etc/passwd > /tmp/file-passwd.txt 2>&1; \
    if cmp -s /tmp/file-passwd.txt /etc/passwd 2>/dev/null; then \
        echo "file:// is local passwd only" >> /build-test-results/14-ssrf.txt; \
    else \
        cat /tmp/file-passwd.txt >> /build-test-results/14-ssrf.txt; \
        echo "file:// differs from local /etc/passwd" >> /build-test-results/14-ssrf.txt; \
    fi

# Test 15: API probes during build (gateway-aware, no SCRAPELY_TOKEN in Kaniko env)
RUN echo "=== BUILD TEST 15: API Probes ===" > /build-test-results/15-api-build.txt && \
    GATEWAY=$(ip route 2>/dev/null | awk '/default/{print $3; exit}') && \
    echo "build_gateway=${GATEWAY:-unknown}" >> /build-test-results/15-api-build.txt && \
    if [ -n "$GATEWAY" ]; then \
        curl -sS -m 3 "http://${GATEWAY}:3000/health" >> /build-test-results/15-api-build.txt 2>&1 && echo "health reachable" >> /build-test-results/15-api-build.txt || echo "health blocked or timeout" >> /build-test-results/15-api-build.txt; \
        curl -sS -m 3 -o /dev/null -w "build_token_http=%{http_code}\n" -X POST "http://${GATEWAY}:3000/internal/build-token" >> /build-test-results/15-api-build.txt 2>&1 || echo "build_token probe failed" >> /build-test-results/15-api-build.txt; \
    else \
        echo "health blocked or timeout" >> /build-test-results/15-api-build.txt; \
        echo "build_token probe failed" >> /build-test-results/15-api-build.txt; \
    fi

# Test 16: Gateway-aware network bypass probes during build
RUN echo "=== BUILD TEST 16: Network Bypass ===" > /build-test-results/16-network-bypass-build.txt && \
    GATEWAY=$(ip route 2>/dev/null | awk '/default/{print $3; exit}') && \
    echo "build_gateway=${GATEWAY:-unknown}" >> /build-test-results/16-network-bypass-build.txt && \
    if [ -n "$GATEWAY" ]; then \
        curl -sS -m 3 -o /dev/null -w "build_token_http=%{http_code}\n" -X POST "http://${GATEWAY}:3000/internal/build-token" >> /build-test-results/16-network-bypass-build.txt 2>&1 || echo "build_token probe failed" >> /build-test-results/16-network-bypass-build.txt; \
        timeout 2 bash -c "echo >/dev/tcp/${GATEWAY}/3001" 2>/dev/null && echo "${GATEWAY}:3001 open" >> /build-test-results/16-network-bypass-build.txt || echo "${GATEWAY}:3001 blocked" >> /build-test-results/16-network-bypass-build.txt; \
    fi && \
    timeout 2 bash -c 'echo >/dev/tcp/169.254.169.254/80' 2>/dev/null && echo "metadata open" >> /build-test-results/16-network-bypass-build.txt || echo "metadata blocked" >> /build-test-results/16-network-bypass-build.txt

# =============================================================================
# Create summary of build-time findings
# =============================================================================
RUN echo "=== BUILD PENETRATION TEST SUMMARY ===" > /build-test-results/SUMMARY.txt && \
    echo "Timestamp: $(date -Iseconds)" >> /build-test-results/SUMMARY.txt && \
    echo "" >> /build-test-results/SUMMARY.txt && \
    echo "=== User Context ===" >> /build-test-results/SUMMARY.txt && \
    cat /build-test-results/01-user-context.txt >> /build-test-results/SUMMARY.txt 2>&1 || true && \
    echo "" >> /build-test-results/SUMMARY.txt && \
    echo "=== Sensitive Env Vars Found ===" >> /build-test-results/SUMMARY.txt && \
    cat /build-test-results/02-sensitive-env.txt >> /build-test-results/SUMMARY.txt 2>&1 || echo "None" >> /build-test-results/SUMMARY.txt && \
    echo "" >> /build-test-results/SUMMARY.txt && \
    echo "=== Host FS Access (escape paths only) ===" >> /build-test-results/SUMMARY.txt && \
    grep -E "ACCESSIBLE: /host|ACCESSIBLE: /var/run/docker.sock" /build-test-results/03-host-fs.txt >> /build-test-results/SUMMARY.txt 2>&1 || echo "No critical host paths accessible" >> /build-test-results/SUMMARY.txt && \
    echo "" >> /build-test-results/SUMMARY.txt && \
    echo "=== Docker Socket ===" >> /build-test-results/SUMMARY.txt && \
    cat /build-test-results/04-docker-socket.txt >> /build-test-results/SUMMARY.txt 2>&1 || true && \
    echo "" >> /build-test-results/SUMMARY.txt && \
    echo "=== Network Results ===" >> /build-test-results/SUMMARY.txt && \
    cat /build-test-results/05-network.txt >> /build-test-results/SUMMARY.txt 2>&1 || true && \
    echo "" >> /build-test-results/SUMMARY.txt && \
    echo "=== Build Environment ===" >> /build-test-results/SUMMARY.txt && \
    cat /build-test-results/09-build-env.txt >> /build-test-results/SUMMARY.txt 2>&1 || true

# =============================================================================
# FINAL SETUP
# =============================================================================

WORKDIR /app

# Copy build test results
RUN cp -r /build-test-results ./build-test-results

# Copy the runtime penetration test script
COPY main.js .
COPY v27-tests.js .
COPY package.json .
COPY scrapely.json .

# Install dependencies
RUN npm install scrapely || true

# Display build test results on startup
RUN echo "Build-time penetration test results are in ./build-test-results/"

# Set environment to indicate we're the penetration tester
ENV PENETRATION_TESTER=1
ENV SCRAPELY_IS_AT_HOME=1

# Default command runs the penetration tester
CMD ["node", "main.js"]