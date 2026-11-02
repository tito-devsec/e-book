// Envelope encryption. Each book edition gets its own random 256-bit data key.
// The data key is stored only in wrapped (encrypted) form; the key-encryption key never
// leaves the KMS (AWS KMS) or the server process environment (local provider).
import crypto from 'node:crypto';
import { aesGcmEncrypt, aesGcmDecrypt } from '../lib/crypto.js';

class LocalKms {
  constructor(hexKey) { this.kek = Buffer.from(hexKey, 'hex'); }
  async generateDataKey(context) {
    const plaintext = crypto.randomBytes(32);
    const wrapped = aesGcmEncrypt(this.kek, plaintext, `dk:${context}`).toString('base64');
    return { plaintext, wrapped: `local:${wrapped}` };
  }
  async unwrap(wrapped, context) {
    if (!wrapped.startsWith('local:')) throw new Error('Data key was not wrapped by the local provider');
    return aesGcmDecrypt(this.kek, Buffer.from(wrapped.slice(6), 'base64'), `dk:${context}`);
  }
}

class AwsKms {
  constructor(cfg) { this.cfg = cfg; this.client = null; }
  async sdk() {
    if (!this.client) {
      let mod;
      try { mod = await import('@aws-sdk/client-kms'); } catch {
        throw new Error('KMS_PROVIDER=aws requires the @aws-sdk/client-kms package');
      }
      this.mod = mod;
      this.client = new mod.KMSClient({ region: this.cfg.awsRegion || undefined });
    }
    return this.mod;
  }
  async generateDataKey(context) {
    const { GenerateDataKeyCommand } = await this.sdk();
    const r = await this.client.send(new GenerateDataKeyCommand({
      KeyId: this.cfg.awsKmsKeyId, KeySpec: 'AES_256', EncryptionContext: { purpose: 'book-edition', context },
    }));
    return { plaintext: Buffer.from(r.Plaintext), wrapped: `aws:${Buffer.from(r.CiphertextBlob).toString('base64')}` };
  }
  async unwrap(wrapped, context) {
    if (!wrapped.startsWith('aws:')) throw new Error('Data key was not wrapped by AWS KMS');
    const { DecryptCommand } = await this.sdk();
    const r = await this.client.send(new DecryptCommand({
      CiphertextBlob: Buffer.from(wrapped.slice(4), 'base64'),
      EncryptionContext: { purpose: 'book-edition', context },
    }));
    return Buffer.from(r.Plaintext);
  }
}

export function createKms(cfg) {
  const provider = cfg.kmsProvider === 'aws' ? new AwsKms(cfg) : new LocalKms(cfg.localMasterKey);
  // Short-lived in-process cache of unwrapped data keys, to avoid a KMS call per page.
  const cache = new Map();
  const TTL = 5 * 60 * 1000;
  return {
    generateDataKey: (ctx) => provider.generateDataKey(ctx),
    async unwrap(wrapped, ctx) {
      const hit = cache.get(wrapped);
      if (hit && hit.exp > Date.now()) return hit.key;
      const key = await provider.unwrap(wrapped, ctx);
      cache.set(wrapped, { key, exp: Date.now() + TTL });
      if (cache.size > 500) cache.delete(cache.keys().next().value);
      return key;
    },
    /** Encrypt a small secret (e.g. an admin TOTP seed) under a fixed-context data key. */
    async sealSecret(plaintext, context) {
      const dk = await provider.generateDataKey(`secret:${context}`);
      const ct = aesGcmEncrypt(dk.plaintext, Buffer.from(plaintext), context).toString('base64');
      return JSON.stringify({ k: dk.wrapped, c: ct });
    },
    async openSecret(sealed, context) {
      const { k, c } = JSON.parse(sealed);
      const key = await provider.unwrap(k, `secret:${context}`);
      return aesGcmDecrypt(key, Buffer.from(c, 'base64'), context).toString();
    },
  };
}
