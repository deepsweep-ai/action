/**
 * Compile-time fixed detector registry (ADR-002; Sprint 02 ADR-gate ruling).
 * NOT a plugin framework: entries are static imports, the array is frozen,
 * and there is no dynamic loading or configuration. Adding a detector means
 * editing this file in a reviewed change. Any proposal for dynamic detector
 * loading supersedes ADR-002 and requires a new ADR first.
 * Order is fixed for deterministic report output.
 */
import type { Detector } from "./detector.js";
export declare const DETECTORS: readonly Detector[];
