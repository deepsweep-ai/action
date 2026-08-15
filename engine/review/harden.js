/**
 * P29 / TEAM-ADR-028 — hardenLedger(): best-available OS protection for the
 * audit ledger, with an HONEST structured report of what it could and could
 * NOT guarantee on this system.
 *
 * THIS IS AN ENGINE LIBRARY FUNCTION, NOT A COMMAND. The CLI is retired as a
 * product surface; the Governance Studio calls this over IPC and renders the
 * report verbatim behind a one-click "Harden ledger" action. There is no
 * `harden` verb and there must never be one.
 *
 * THE CONTRACT THAT MATTERS: no silent overclaiming. A control that could not
 * be applied is a FIRST-CLASS RESULT — "I could not do X because Y" — not an
 * error and not an omission. Degrading without admin rights is normal and is
 * reported as such. A platform with no available control reports
 * `not-hardened`, never a quiet success.
 *
 * WHAT EACH CONTROL BUYS (and what it does not):
 *  - linux  `chattr +a`      — append-only inode flag. Rewrites and unlinks
 *                              fail even for the owner. Requires
 *                              CAP_LINUX_IMMUTABLE (root) and an ext2/3/4 or
 *                              xfs filesystem; root can clear it again.
 *  - darwin `chflags uappnd` — user append-only. Applies WITHOUT root, which
 *                              is the common developer case. The owner can
 *                              clear it with `chflags nouappnd`, so it raises
 *                              the cost of a silent rewrite; it does not make
 *                              one impossible.
 *  - darwin `chflags schg`   — system immutable. Root only, and blocks
 *                              appends too, so it suits an ARCHIVED ledger,
 *                              not a live one.
 *  - win32  `icacls /deny`   — deny WriteData/AppendData/DeleteChild on the
 *                              current user's SID. An administrator (or the
 *                              file owner exercising WRITE_DAC) can rewrite
 *                              the ACL.
 *
 * Every one of those is defeatable by the same OS user. That is the honest
 * threat model (docs/security.md): the guarantee is PREVENT + tamper-EVIDENCE
 * + SURVIVE + RESPOND, and hardening is the PREVENT leg only.
 *
 * NO RELEASE FUNCTION IS SHIPPED. Loosening hardening is a deliberate human
 * shell action (`chflags nouappnd`, `chattr -a`, `icacls /remove:d`), not an
 * engine capability — an unharden API would hand an agent a one-call
 * bypass wrapped in our own trust boundary.
 *
 * Determinism: `nowIso` is injected, steps are emitted in a fixed order, and
 * the report carries a STORE-RELATIVE target path only (never an absolute
 * path — the privacy gate forbids them in any artifact).
 */
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { STORE_DIR } from "./store.js";
import { LEDGER_FILE } from "./ledger.js";
import { LEDGER_SIG_FILE } from "./ledger-sign.js";
export const HARDEN_REPORT_SCHEMA_VERSION = 1;
/** Map an exit code to a failure class. No stderr ever crosses this boundary:
 * a child's stderr can echo a path or a filename, and the report is a
 * cloud-renderable artifact. */
export function classifyHardenExit(code) {
    if (code === 0)
        return null;
    if (code === 1)
        return "not-permitted";
    if (code === 127 || code === null)
        return "not-found";
    return "failed";
}
/** The production seam. Fixed command names and argv arrays — no shell, and
 * no user-controlled string ever reaches a command position. */
export function nodeHardenSyscalls() {
    return {
        platform: process.platform,
        /* c8 ignore next -- reason: process.getuid is absent on win32; the suite runs the POSIX arm, and the injected-seam tests cover both elevated states. */
        elevated: typeof process.getuid === "function" ? process.getuid() === 0 : false,
        run(command, args) {
            const r = spawnSync(command, [...args], { stdio: "ignore", shell: false });
            /* c8 ignore next -- reason: spawnSync only sets .error for spawn-level faults (ENOENT/EACCES on the binary itself); staging one portably would require removing /usr/bin/chflags. */
            const code = r.error !== undefined ? null : r.status;
            return { ok: code === 0, code, failure: classifyHardenExit(code) };
        },
        exists: (absolutePath) => existsSync(absolutePath),
    };
}
const PLANS = {
    linux: [
        {
            control: "append-only-flag",
            mechanism: "chattr +a",
            command: "chattr",
            args: (t) => ["+a", t],
            needsElevation: true,
            guarantees: "the file can only be appended to: rewrites, truncation and unlink are refused by the kernel, for every process including this one",
            doesNotGuarantee: "root can clear the flag again with `chattr -a`, and the flag is only supported on ext2/3/4, xfs and btrfs",
        },
    ],
    darwin: [
        {
            control: "append-only-flag",
            mechanism: "chflags uappnd",
            command: "chflags",
            args: (t) => ["uappnd", t],
            needsElevation: false,
            guarantees: "the file can only be appended to: rewrites, truncation and unlink are refused by the kernel while the flag is set",
            doesNotGuarantee: "the file's owner can clear it with `chflags nouappnd` without any elevation — this raises the cost of a silent rewrite, it does not make one impossible",
        },
        {
            control: "immutable-flag",
            mechanism: "chflags schg",
            command: "chflags",
            args: (t) => ["schg", t],
            needsElevation: true,
            guarantees: "the file cannot be modified at all below securelevel 1 — suitable for an ARCHIVED ledger",
            doesNotGuarantee: "it also blocks APPENDS, so a live ledger cannot carry it; and it requires root to set and to clear",
        },
    ],
    win32: [
        {
            control: "deny-write-acl",
            mechanism: "icacls /deny WriteData,AppendData,DeleteChild",
            command: "icacls",
            args: (t) => [t, "/deny", "*S-1-5-32-545:(WD,DC)"],
            needsElevation: false,
            guarantees: "NTFS refuses WriteData and DeleteChild for the Users group on this file, so an in-place rewrite fails",
            doesNotGuarantee: "an administrator, or the file owner exercising WRITE_DAC, can rewrite the ACL and remove the deny entry",
        },
    ],
};
const RESIDUAL_RISKS = [
    "An agent that runs as the same OS user as you can clear these flags with a shell command; no local product can make a file absolutely unwritable against its own user.",
    "Hardening protects the file, not the disk: deleting the whole workspace, restoring a snapshot, or writing from a container that mounts the directory all bypass it.",
    "The ledger only proves what it recorded. Hardening is the PREVENT leg; the hash chain, per-entry signatures and escrowed anchors are what make an unprevented tamper EVIDENT.",
];
/**
 * Apply the best OS protection available for the ledger and its signature
 * sidecar, and report exactly what happened.
 *
 * Never throws for a protection failure: a refused control is a reported step.
 */
export function hardenLedger(workspaceRoot, opts) {
    const sys = opts.syscalls ?? nodeHardenSyscalls();
    const plans = PLANS[sys.platform] ?? [];
    const relTargets = [`${STORE_DIR}/${LEDGER_FILE}`, `${STORE_DIR}/${LEDGER_SIG_FILE}`].sort();
    const absTargets = relTargets.map((rel) => resolve(join(workspaceRoot, rel)));
    const present = absTargets.filter((p) => sys.exists(p));
    const steps = [];
    if (plans.length === 0) {
        steps.push({
            control: "append-only-flag",
            mechanism: "(none available)",
            status: "unsupported",
            guarantees: null,
            doesNotGuarantee: "nothing was applied, so the ledger has exactly the protection the filesystem gives any ordinary file",
            why: `I could not apply any OS-level write protection because platform "${sys.platform}" has no append-only or deny-write mechanism DeepSweep knows how to use. The ledger remains tamper-EVIDENT (hash chain, per-entry signatures, escrowed anchors) but it is not self-protected on this system.`,
        });
    }
    else if (present.length === 0) {
        for (const plan of plans) {
            steps.push({
                control: plan.control,
                mechanism: plan.mechanism,
                status: "not-attempted",
                guarantees: null,
                doesNotGuarantee: plan.doesNotGuarantee,
                why: `I could not apply ${plan.mechanism} because neither ${relTargets.join(" nor ")} exists yet. Run a review first so the ledger is created, then harden.`,
            });
        }
    }
    else {
        for (const plan of plans) {
            if (plan.needsElevation && !sys.elevated) {
                steps.push({
                    control: plan.control,
                    mechanism: plan.mechanism,
                    status: "refused",
                    guarantees: null,
                    doesNotGuarantee: plan.doesNotGuarantee,
                    why: `I could not apply ${plan.mechanism} because it requires administrator/root privileges and this process is not elevated.`,
                });
                continue;
            }
            const failures = [];
            for (const target of present) {
                const r = sys.run(plan.command, plan.args(target));
                if (!r.ok)
                    failures.push(r.failure ?? "failed");
            }
            if (failures.length === 0) {
                steps.push({
                    control: plan.control,
                    mechanism: plan.mechanism,
                    status: "applied",
                    guarantees: plan.guarantees,
                    doesNotGuarantee: plan.doesNotGuarantee,
                    why: `Applied ${plan.mechanism} to ${present.length} of ${relTargets.length} store file(s).`,
                });
            }
            else {
                steps.push({
                    control: plan.control,
                    mechanism: plan.mechanism,
                    status: "refused",
                    guarantees: null,
                    doesNotGuarantee: plan.doesNotGuarantee,
                    why: `I could not apply ${plan.mechanism} because the operating system refused it (${[...new Set(failures)].sort().join(", ")}). On this platform that usually means missing privileges or an unsupported filesystem.`,
                });
            }
        }
    }
    const applied = steps.filter((s) => s.status === "applied").length;
    const overall = applied === 0 ? "not-hardened" : applied === steps.length ? "hardened" : "partially-hardened";
    const summary = applied === 0
        ? `No OS-level protection could be applied on ${sys.platform}. The ledger is still tamper-evident, but nothing prevents a rewrite.`
        : `${applied} of ${steps.length} available control(s) applied on ${sys.platform}. This makes a silent rewrite harder; it does not make one impossible.`;
    return {
        schemaVersion: HARDEN_REPORT_SCHEMA_VERSION,
        platform: sys.platform,
        elevated: sys.elevated,
        targets: relTargets,
        attemptedAt: opts.nowIso,
        steps,
        overall,
        summary,
        residualRisks: RESIDUAL_RISKS,
    };
}
/** Plain-text rendering. The Studio may render the structure itself; this is
 * the canonical wording so both surfaces say the same thing. */
export function renderHardenReport(r) {
    const lines = [
        `Ledger hardening — ${r.platform}${r.elevated ? " (elevated)" : " (not elevated)"}`,
        `Result: ${r.overall.toUpperCase()}`,
        r.summary,
        "",
        `Targets: ${r.targets.join(", ")}`,
        "",
    ];
    for (const s of r.steps) {
        lines.push(`[${s.status}] ${s.control} — ${s.mechanism}`);
        lines.push(`  ${s.why}`);
        if (s.guarantees !== null)
            lines.push(`  Guarantees: ${s.guarantees}`);
        lines.push(`  Does not guarantee: ${s.doesNotGuarantee}`);
    }
    lines.push("", "Residual risks (true even when every control applies):");
    for (const risk of r.residualRisks)
        lines.push(`  - ${risk}`);
    return lines.join("\n");
}
