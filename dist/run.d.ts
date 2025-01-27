import * as CacheControl from './cache-control.js';
export declare function run({ bucket, prefix, dirPath, isDelete, cacheControlJson, cacheControlMergePolicy, defaultCacheControl }: {
    bucket: string;
    prefix: string;
    dirPath: string;
    isDelete: boolean;
    cacheControlJson: CacheControl.Pattern;
    cacheControlMergePolicy: string;
    defaultCacheControl: string;
}): Promise<void>;
