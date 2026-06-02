/**
 * PID limit detection for run containers (Docker PidsLimit + gVisor).
 * No platform env vars — cgroup, /proc/self/limits, ulimit, and fork probe only.
 */

/** Matches worker RUN_CONTAINER_PIDS_LIMIT default */
export const PLATFORM_PIDS_LIMIT_DEFAULT = 512;

export function parseMaxProcessesFromProcLimits(runCmd) {
    const raw = runCmd('grep -E "^Max processes" /proc/self/limits 2>/dev/null || true').output;
    const m = raw.match(/Max processes\s+(\d+|\S+)\s+(\d+|\S+)/);
    if (!m) return { soft: null, hard: null, raw: raw.trim() || null };
    const soft = parseLimitToken(m[1]);
    const hard = parseLimitToken(m[2]);
    return { soft, hard, raw: raw.trim() };
}

function parseLimitToken(tok) {
    if (!tok || tok === 'unlimited') return null;
    const n = parseInt(tok, 10);
    return Number.isFinite(n) && n > 0 ? n : null;
}

export function readCgroupPidsMax(runCmd) {
    const pidsMaxVal = runCmd(
        'cat /sys/fs/cgroup/pids.max 2>/dev/null || cat /sys/fs/cgroup/pids/pids.max 2>/dev/null || echo max',
    ).output.trim();
    const n = parseInt(pidsMaxVal, 10);
    const cgroupLimited = pidsMaxVal !== 'max' && pidsMaxVal !== 'unknown' && Number.isFinite(n) && n > 0;
    return { pidsMaxVal, cgroupLimited, cgroupLimit: cgroupLimited ? n : null };
}

export function runForkProbe(runCmd, { maxAttempts = 600, timeoutMs = 15000 } = {}) {
    const forkProbe = runCmd(
        `sh -c 'hits=0; for i in $(seq 1 ${maxAttempts}); do ( true & ) 2>/dev/null && hits=$((hits+1)) || break; done; wait 2>/dev/null; echo $hits'`,
        timeoutMs,
    );
    const forkHit = parseInt((forkProbe.output.match(/[0-9]+/) || ['0'])[0], 10);
    const forkLimited = forkHit > 0 && forkHit < maxAttempts;
    return { forkHit, forkLimited, maxAttempts };
}

/**
 * Run all PID limit signals once. `present` / `enforced` true if any signal shows a cap.
 */
export function detectPidsLimitSignals(runCmd) {
    const cgroup = readCgroupPidsMax(runCmd);
    const proc = parseMaxProcessesFromProcLimits(runCmd);
    const nprocRaw = runCmd('ulimit -u').output.trim();
    const nprocUlimit = parseInt(nprocRaw, 10);
    const ulimitLimited = Number.isFinite(nprocUlimit) && nprocUlimit > 0 && nprocUlimit < 65536;

    const fork = runForkProbe(runCmd);

    const procLimited = proc.soft != null && proc.soft > 0 && proc.soft < 65536;
    const visible = cgroup.cgroupLimited || procLimited || ulimitLimited || fork.forkLimited;

    const sources = [];
    if (cgroup.cgroupLimited) sources.push(`cgroup pids.max=${cgroup.cgroupLimit}`);
    if (procLimited) sources.push(`Max processes=${proc.soft}`);
    if (ulimitLimited) sources.push(`ulimit -u=${nprocUlimit}`);
    if (fork.forkLimited) sources.push(`fork probe stopped at ${fork.forkHit}`);

    const inferredCap = cgroup.cgroupLimit || proc.soft || (ulimitLimited ? nprocUlimit : null)
        || (fork.forkLimited ? fork.forkHit : null)
        || PLATFORM_PIDS_LIMIT_DEFAULT;

    return {
        ...cgroup,
        proc,
        nprocUlimit: Number.isFinite(nprocUlimit) ? nprocUlimit : nprocRaw,
        ulimitLimited,
        procLimited,
        fork,
        visible,
        present: visible,
        enforced: visible,
        inferredCap,
        sources,
    };
}
