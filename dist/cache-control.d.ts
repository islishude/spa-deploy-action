export interface Pattern {
    [glob: string]: string;
}
export declare const defaultPolicy = "public,max-age=86400,stale-while-revalidate=2592000";
export declare const optimizedPolicy = "public,max-age=31536000,immutable";
export declare const indexHtmlPolicy = "public,max-age=60,stale-while-revalidate=2592000";
export type MergePolicy = 'upsert' | 'replace';
export declare const builtin: Map<string, string>;
export declare function Merge(i: Pattern, policy: MergePolicy): Map<string, string>;
export declare function Get(filePath: string, patterns: Map<string, string>, _default: string): string | undefined;
