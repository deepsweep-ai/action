/**
 * Tiny, dependency-free copy helpers for rendered summaries (S1.10 polish).
 * Fixes the "1 Cursor rule file(s)" defect class: counts always agree with
 * their noun (and, where the phrase carries one, its verb).
 */
/**
 * Render a count with a grammatically agreeing phrase.
 * `singular`/`plural` are full phrases so verb agreement rides along, e.g.
 * `countNoun(n, "rule file auto-applies", "rule files auto-apply")`.
 * `plural` defaults to `singular + "s"` for plain nouns.
 */
export declare function countNoun(count: number, singular: string, plural?: string): string;
