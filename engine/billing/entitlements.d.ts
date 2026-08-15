/**
 * Revenue layer — entitlements & tier gates.
 * SYNCED TO STRIPE (source of truth, pulled 2026-07-27, account acct_1S2EsWLLFqn3U97P).
 * Tiers: Free / Pro / Team / Enterprise. Flat per-seat, no usage metering (answers PP-3).
 *
 * Stripe IDs are the single source of truth shared by the pricing page, checkout, and these
 * gates — do not hardcode prices in the UI; read STRIPE_PRICES here.
 */
export type Tier = "free" | "pro" | "team" | "enterprise";
export type Feature = "review" | "identity" | "authorization" | "protect" | "auditLocal" | "governanceScore" | "exactLocations" | "oneClickRemediation" | "mcpPinning" | "replay30" | "verifiedBadge" | "teamPolicyBundles" | "delegatedApprovals" | "ciCdGating" | "restApi" | "auditLogs90" | "seats10" | "complianceEvidence" | "ssoScim" | "orgPolicyDistribution" | "replayUnlimited" | "airGap" | "sla" | "dedicatedSupport";
export interface StripePrice {
    productId: string;
    monthly: string | null;
    annual: string | null;
}
/** Live Stripe identifiers (2026-07-27). Enterprise monthly is a $0 "contact sales" placeholder. */
export declare const STRIPE_PRICES: Record<Tier, StripePrice>;
export interface Plan {
    tier: Tier;
    displayName: string;
    /** Display cents (USD). null = custom / contact sales. */
    monthlyCents: number | null;
    annualCents: number | null;
    seats: number;
    features: Feature[];
    replayRetentionDays: number;
    popular?: boolean;
    blurb: string;
}
export declare const PLANS: Record<Tier, Plan>;
export interface Entitlements {
    tier: Tier;
    seats: number;
    features: Set<Feature>;
    replayRetentionDays: number;
}
export declare function entitlementsFor(tier: Tier, seats?: number): Entitlements;
export declare function isEntitled(e: Entitlements, feature: Feature): boolean;
export declare function requireFeature(e: Entitlements, feature: Feature): void;
export declare class EntitlementError extends Error {
    readonly feature: Feature;
    readonly currentTier: Tier;
    readonly requiredTier: string;
    constructor(feature: Feature, currentTier: Tier, requiredTier: string);
}
/** Deterministic monthly revenue (USD dollars) for a seat mix; custom tiers excluded (null price). */
export declare function monthlyRevenueUsd(seatMix: Partial<Record<Tier, number>>): number;
/** Display helper: "$19" / "$99" / "Custom". */
export declare function priceLabel(tier: Tier, cycle?: "monthly" | "annual"): string;
