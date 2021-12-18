'use strict';
import * as assert from 'assert';
import { debuglog } from 'util';
import {
  CipherGCM,
  CipherGCMTypes,
  createCipheriv,
  createDecipheriv,
  createHmac,
  DecipherGCM,
  pbkdf2Sync,
  randomBytes,
} from 'crypto';
import * as constantTimeCompare from 'scmp';

const debug = debuglog('midway:cookies');

const replacer = {
  '/': '_',
  '+': '-',
  '=': '',
};

// patch from https://github.com/crypto-utils/keygrip
// encrypt code from https://github.com/btxtiger/encrypt-cookie/blob/master/src/cryptography.ts
export class Keygrip {
  private keys;
  private hash;

  constructor(keys?: string[]) {
    assert(
      Array.isArray(keys) && keys.length,
      'keys must be provided and should be an array'
    );
    this.keys = keys;
    this.hash = 'sha256';
  }

  // encrypt a message
  encrypt(plainText: string, key?): string {
    key = key || this.keys[0];
    try {
      plainText = String(plainText);
      const algorithm: CipherGCMTypes = getAlgorithm();

      // Generate random salt -> 64 bytes
      const salt = randomBytes(64);

      // Generate random initialization vector -> 16 bytes
      const iv = randomBytes(16);

      // Generate random count of iterations between 10.000 - 99.999 -> 5 bytes
      const iterations =
        Math.floor(Math.random() * (99999 - 10000 + 1)) + 10000;

      // Derive encryption key
      const encryptionKey = deriveKeyFromPassword(
        key,
        salt,
        Math.floor(iterations * 0.47 + 1337)
      );

      // Create cipher
      const cipher: CipherGCM = createCipheriv(algorithm, encryptionKey, iv);

      // Update the cipher with data to be encrypted and close cipher
      const encryptedData = Buffer.concat([
        cipher.update(plainText, 'utf8'),
        cipher.final(),
      ]);

      // Get authTag from cipher for decryption // 16 bytes
      const authTag = cipher.getAuthTag();

      // Join all data into single string, include requirements for decryption
      const output = Buffer.concat([
        salt,
        iv,
        authTag,
        Buffer.from(iterations.toString()),
        encryptedData,
      ]).toString('hex');

      return getEncryptedPrefix() + output;
    } catch (err) {
      debug('crypt error', err.stack);
      return undefined;
    }
  }

  // decrypt a single message
  // returns false on bad decrypts
  decrypt(cipherText: string, key?) {
    if (!key) {
      // decrypt every key
      const keys = this.keys;
      for (let i = 0; i < keys.length; i++) {
        const value = this.decrypt(cipherText, keys[i]);
        if (value !== false) return { value, index: i };
      }
      return false;
    }

    try {
      const algorithm: CipherGCMTypes = getAlgorithm();
      const cipherTextParts = cipherText.split(getEncryptedPrefix());

      // If it's not encrypted by this, reject with undefined
      if (cipherTextParts.length !== 2) {
        // console.warn('Could not determine the beginning of the cipherText. Maybe not encrypted by this method.');
        return void 0;
      } else {
        cipherText = cipherTextParts[1];
      }

      const inputData: Buffer = Buffer.from(cipherText, 'hex');

      // Split cipherText into partials
      const salt: Buffer = inputData.slice(0, 64);
      const iv: Buffer = inputData.slice(64, 80);
      const authTag: Buffer = inputData.slice(80, 96);
      const iterations: number = parseInt(
        inputData.slice(96, 101).toString('utf-8'),
        10
      );
      const encryptedData: Buffer = inputData.slice(101);

      // Derive key
      const decryptionKey = deriveKeyFromPassword(
        key,
        salt,
        Math.floor(iterations * 0.47 + 1337)
      );

      // Create decipher
      const decipher: DecipherGCM = createDecipheriv(
        algorithm,
        decryptionKey,
        iv
      );
      decipher.setAuthTag(authTag);

      // Decrypt data
      return (
        decipher.update(encryptedData as any, 'binary', 'utf-8') +
        decipher.final('utf-8')
      );
    } catch (err) {
      debug('crypt error', err.stack);
      return false;
    }
  }

  sign(data, key?) {
    // default to the first key
    key = key || this.keys[0];

    return createHmac(this.hash, key)
      .update(data)
      .digest('base64')
      .replace(/\/|\+|=/g, x => replacer[x]);
  }

  verify(data, digest) {
    const keys = this.keys;
    for (let i = 0; i < keys.length; i++) {
      if (
        constantTimeCompare(
          Buffer.from(digest),
          Buffer.from(this.sign(data, keys[i]))
        )
      ) {
        debug('data %s match key %s', data, keys[i]);
        return i;
      }
    }
    return -1;
  }
}

/**
 * Get encryption/decryption algorithm
 */
function getAlgorithm(): CipherGCMTypes {
  return 'aes-256-gcm';
}

/**
 * Get encrypted string prefix
 */
function getEncryptedPrefix(): string {
  return 'enc::';
}

/**
 * Derive 256 bit encryption key from password, using salt and iterations -> 32 bytes
 * @param password
 * @param salt
 * @param iterations
 */
function deriveKeyFromPassword(
  password,
  salt: Buffer,
  iterations: number
): Buffer {
  return pbkdf2Sync(password, salt, iterations, 32, 'sha512');
}
