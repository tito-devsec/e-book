// Private object storage. Objects are never served directly: every read goes through
// an authorized API route. Local driver writes outside the web root; S3 driver expects a
// private bucket (Block Public Access on, SSE-KMS recommended).
import fs from 'node:fs/promises';
import path from 'node:path';

class LocalStorage {
  constructor(dir) { this.root = path.resolve(dir); }
  file(key) {
    if (!/^[a-z0-9/_.-]+$/i.test(key) || key.includes('..')) throw new Error('Invalid storage key');
    return path.join(this.root, key);
  }
  async put(key, body) {
    const f = this.file(key);
    await fs.mkdir(path.dirname(f), { recursive: true, mode: 0o700 });
    await fs.writeFile(f, body, { mode: 0o600 });
  }
  async get(key) { return fs.readFile(this.file(key)); }
  async delete(key) { await fs.rm(this.file(key), { force: true }); }
}

class S3Storage {
  constructor(cfg) { this.cfg = cfg; }
  async client() {
    if (!this.c) {
      let mod;
      try { mod = await import('@aws-sdk/client-s3'); } catch {
        throw new Error('STORAGE_DRIVER=s3 requires the @aws-sdk/client-s3 package');
      }
      this.mod = mod;
      this.c = new mod.S3Client({
        region: this.cfg.awsRegion || undefined,
        endpoint: this.cfg.s3Endpoint || undefined,
        forcePathStyle: this.cfg.s3ForcePathStyle,
      });
    }
    return this.c;
  }
  async put(key, body, mime = 'application/octet-stream') {
    const c = await this.client();
    await c.send(new this.mod.PutObjectCommand({
      Bucket: this.cfg.s3Bucket, Key: key, Body: body, ContentType: mime,
      ServerSideEncryption: this.cfg.awsKmsKeyId ? 'aws:kms' : 'AES256',
      SSEKMSKeyId: this.cfg.awsKmsKeyId || undefined,
    }));
  }
  async get(key) {
    const c = await this.client();
    const r = await c.send(new this.mod.GetObjectCommand({ Bucket: this.cfg.s3Bucket, Key: key }));
    return Buffer.from(await r.Body.transformToByteArray());
  }
  async delete(key) {
    const c = await this.client();
    await c.send(new this.mod.DeleteObjectCommand({ Bucket: this.cfg.s3Bucket, Key: key }));
  }
}

export function createStorage(cfg) {
  if (cfg.storageDriver === 's3') {
    if (!cfg.s3Bucket) throw new Error('S3_BUCKET is required when STORAGE_DRIVER=s3');
    return new S3Storage(cfg);
  }
  return new LocalStorage(cfg.storageLocalDir);
}
