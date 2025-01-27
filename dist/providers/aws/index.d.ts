import type { Provider } from '../index.js';
export default class S3Provider implements Provider {
    private bucket;
    private prefix?;
    private client;
    constructor(bucket: string, prefix?: string | undefined);
    listObjects(): Promise<string[]>;
    putObject(dir: string, fpath: string, contentType: string, cacheControl?: string): Promise<void>;
    deleteObjects(key: string): Promise<void>;
}
