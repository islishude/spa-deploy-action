export interface Provider {
    listObjects(): Promise<string[]>;
    putObject(dir: string, fpath: string, contentType: string, cacheControl?: string): Promise<void>;
    deleteObjects(key: string): Promise<void>;
}
