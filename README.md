# Scrapely Container Penetration Tester (v2.7.0)

Security testing actor for Scrapely container isolation. Failures indicate platform gaps to fix in `scrapely/` — this package only contains tests.

## Categories (22)

| Category | Focus |
|----------|--------|
| `buildTime` | Dockerfile build artifacts |
| `buildEnvironment` | Live build-mirror probes |
| `containerHardening` | CapDrop, NoNewPrivs, `/etc` writable, non-root, AppArmor |
| `scrapelyPlatform` | Env secrets, API URL, CDP |
| `networkIsolation` | RFC1918, metadata, DNS, egress |
| `networkBypass` | **v2.7** IPv6, UDP, ICMP, redirects, host registry |
| `perUserNetwork` | 172.32–47 subnets, cross-user gateways |
| `registryAccess` | Auth, catalog, manifest, push |
| `gvisorEscape` | runsc, devices, eBPF, user ns |
| `containerBreakout` | docker.sock, mounts, setuid |
| `resourceExhaustion` | Memory, PIDs, fork bomb, fd limits |
| `infoDisclosure` | Secrets in env/files/processes |
| `privateApiEscape` | :3000 reachability vs abuse |
| `maliciousActor` | Active root breakout attempts |
| `ssrfAttacks` | HTTP/file/gopher SSRF |
| `apiAbuse` | Token scope, admin routes, foreign storage |
| `lifecyclePaths` | **v2.7** Post-metamorph, reboot/metamorph auth |
| `escapeProbes` | mount, unshare, procfs, ptrace |
| `infraSurface` | Kaniko paths, subnet alignment, build artifacts |

## Failure → platform fix (cheat sheet)

| Failure | Likely fix in `scrapely/` |
|---------|--------------------------|
| `/etc` writable, LD_PRELOAD | `ReadonlyRootfs: true` in `worker.ts` |
| UID 0 | Enforce `User: node` on run containers |
| PidsLimit / fork bomb | `PidsLimit` in `worker.ts` |
| AppArmor missing post-metamorph | `apparmor=scrapely-run` on metamorph container |
| Subnet not 172.32–47 | Fix network fallback / `config.ts` |
| IPv6 bypass | ip6tables or disable IPv6 on user networks |
| RFC1918 reachable | Run `setup-network-isolation.sh`, persist iptables |

## Usage

```bash
cd penetration-tester
npm install
node main.js
```

Deploy as Scrapely actor; rebuild image on platform so build-time probes (gateway-aware) run in Kaniko.

## Files

- `main.js` — Core suite (~157 tests) + orchestration
- `v27-tests.js` — v2.7 expansion (~60 tests)
- `Dockerfile` — Build-time probes (tests 1–16)
- `scrapely.json` — Actor metadata

## Severity

- **Hard fail (✗)** — vulnerability or missing control; fix platform
- **Informational (~)** — expected quirk, skipped probe, or in-container-only note
- **Pass (✓)** — control verified
