import { type StudioInput } from "./studio.js";
import { type SurfaceContext } from "./surface.js";
/** The sanctioned cloud-plane bases (founder directive; health-verified). */
export declare const API_BASE = "https://api.deepsweep.ai/v1";
export declare const API_BASE_DEV = "https://api-dev.deepsweep.ai/v1";
export interface StudioServerOptions {
    initialRoot: string;
    toolVersion: string;
    userConfigRoot?: string;
    /** Injectable for deterministic tests; defaults to a random session token. */
    token?: string;
    /** Injectable clock (determinism in tests). */
    now?: () => Date;
    port?: number;
    /**
     * TEAM-ADR-030 — the surface this server renders FOR, resolved once by the
     * composition root that started it (`resolveSurface`). Omitted → 'web',
     * which is correct for the served Studio and is the fail-closed default
     * everywhere else. This server never resolves the surface itself: it has
     * no access to the client's bootstrap signals, and `serve` mode is NOT a
     * surface signal — the desktop app serves too.
     */
    surfaceContext?: SurfaceContext;
}
export interface StudioServer {
    readonly url: string;
    readonly port: number;
    readonly token: string;
    close(): Promise<void>;
}
/** Assemble a StudioInput by running one review over `root` (appends one
 * ledger entry — callers cache the result; see GET idempotence above). */
export declare function assembleStudioInput(root: string, toolVersion: string, userConfigRoot: string | undefined, now: (() => Date) | undefined): StudioInput;
export declare function startStudioServer(options: StudioServerOptions): Promise<StudioServer>;
