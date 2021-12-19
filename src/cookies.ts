import * as assert from 'assert';
import { Cookie } from './cookie';
import { CookieGetOptions, CookieSetOptions } from './interface';
import { Keygrip } from './keygrip';
import { isSameSiteNoneCompatible as _isSameSiteNoneCompatible } from 'should-send-same-site-none';

const KEYS_ARRAY = Symbol('midwayCookies:keysArray');
const KEYS = Symbol('midwayCookies:keys');
const keyCache = new Map();

/**
 * cookies extend pillarjs/cookies, add encrypt and decrypt
 */
export class Cookies {
  private readonly _defaultCookieOptions;
  public ctx;
  public secure;
  public app;

  constructor(ctx, keys, defaultCookieOptions?: CookieSetOptions) {
    this[KEYS_ARRAY] = keys;
    // default cookie options
    this._defaultCookieOptions = defaultCookieOptions;
    this.ctx = ctx;
    this.secure = this.ctx.secure;
    this.app = ctx.app;
  }

  get keys() {
    if (!this[KEYS]) {
      const keysArray = this[KEYS_ARRAY];
      assert(
        Array.isArray(keysArray),
        '.keys required for encrypt/sign cookies'
      );
      const cache = keyCache.get(keysArray);
      if (cache) {
        this[KEYS] = cache;
      } else {
        this[KEYS] = new Keygrip(this[KEYS_ARRAY]);
        keyCache.set(keysArray, this[KEYS]);
      }
    }

    return this[KEYS];
  }

  /**
   * This extracts the cookie with the given name from the
   * Cookie header in the request. If such a cookie exists,
   * its value is returned. Otherwise, nothing is returned.
   * @param name The cookie's unique name.
   * @param opts Optional. The options for cookie's getting.
   * @returns The cookie's value according to the specific name.
   */
  public get(name: string, opts?: CookieGetOptions): string | undefined {
    opts = opts || {};
    const signed = computeSigned(opts);

    const header = this.ctx.get('cookie');
    if (!header) return;

    const match = header.match(getPattern(name));
    if (!match) return;

    let value = match[1];
    if (!opts.encrypt && !signed) return value;

    // signed
    if (signed) {
      const sigName = name + '.sig';
      const sigValue = this.get(sigName, { signed: false });
      if (!sigValue) return;

      const raw = name + '=' + value;
      const index = this.keys.verify(raw, sigValue);
      if (index < 0) {
        // can not match any key, remove ${name}.sig
        this.set(sigName, null, { path: '/', signed: false });
        return;
      }
      if (index > 0) {
        // not signed by the first key, update sigValue
        this.set(sigName, this.keys.sign(raw), { signed: false });
      }
      return value;
    }

    // encrypt
    value = urlSafeDecode(value);
    const res = this.keys.decrypt(value);
    return res ? res.value.toString() : undefined;
  }

  /**
   * This sets the given cookie in the response and returns
   * the current context to allow chaining.If the value is omitted,
   * an outbound header with an expired date is used to delete the cookie.
   * @param name The cookie's unique name.
   * @param value Optional. The cookie's real value.
   * @param opts Optional. The options for cookie's setting.
   * @returns The current 'Cookie' instance.
   */
  public set(name: string, value: string, opts?: CookieSetOptions): this;
  public set(name: string, opts?: CookieSetOptions): this;
  public set(name: string, value?: any, opts?: any): this {
    if (!opts && typeof value !== 'string') {
      opts = value;
      value = '';
    }
    opts = Object.assign({}, this._defaultCookieOptions, opts);
    const signed = computeSigned(opts);
    value = value || '';
    if (!this.secure && opts.secure) {
      throw new Error('Cannot send secure cookie over unencrypted connection');
    }

    let headers = this.ctx.response.get('set-cookie') || [];
    if (!Array.isArray(headers)) headers = [headers];

    // encrypt
    if (opts.encrypt) {
      value = value && urlSafeEncode(this.keys.encrypt(value));
    }

    // http://browsercookielimits.squawky.net/
    if (value.length > 4093) {
      this.app.emit('cookieLimitExceed', { name, value, ctx: this.ctx });
    }

    // https://github.com/linsight/should-send-same-site-none
    // fixed SameSite=None: Known Incompatible Clients
    if (
      opts.sameSite &&
      typeof opts.sameSite === 'string' &&
      opts.sameSite.toLowerCase() === 'none'
    ) {
      const userAgent = this.ctx.get('user-agent');
      if (
        !this.secure ||
        (userAgent && !this.isSameSiteNoneCompatible(userAgent))
      ) {
        // Non-secure context or Incompatible clients, don't send SameSite=None property
        opts.sameSite = false;
      }
    }

    const cookie = new Cookie(name, value, opts);

    // if user not set secure, reset secure to ctx.secure
    if (opts.secure === undefined) cookie.attrs.secure = this.secure;

    headers = pushCookie(headers, cookie);

    // signed
    if (signed) {
      cookie.value = value && this.keys.sign(cookie.toString());
      cookie.name += '.sig';
      headers = pushCookie(headers, cookie);
    }

    this.ctx.set('set-cookie', headers);
    return this;
  }

  protected isSameSiteNoneCompatible(userAgent) {
    // Chrome >= 80.0.0.0
    const result = parseChromiumAndMajorVersion(userAgent);
    if (result.chromium) return result.majorVersion >= 80;
    return _isSameSiteNoneCompatible(userAgent);
  }
}

// https://github.com/linsight/should-send-same-site-none/blob/master/index.js#L86
function parseChromiumAndMajorVersion(userAgent) {
  const m = /Chrom[^ /]+\/(\d+)[.\d]* /.exec(userAgent);
  if (!m) return { chromium: false, version: null };
  // Extract digits from first capturing group.
  return { chromium: true, majorVersion: parseInt(m[1]) };
}

const patternCache = new Map();
function getPattern(name) {
  const cache = patternCache.get(name);
  if (cache) return cache;
  const reg = new RegExp(
    '(?:^|;) *' + name.replace(/[-[\]{}()*+?.,\\^$|#\s]/g, '\\$&') + '=([^;]*)'
  );
  patternCache.set(name, reg);
  return reg;
}

function computeSigned(opts) {
  // encrypt default to false, signed default to true.
  // disable singed when encrypt is true.
  if (opts.encrypt) return false;
  return opts.signed !== false;
}

function pushCookie(cookies, cookie) {
  if (cookie.attrs.overwrite) {
    cookies = cookies.filter(c => !c.startsWith(cookie.name + '='));
  }
  cookies.push(cookie.toHeader());
  return cookies;
}

export function urlSafeEncode(encode: string): string {
  return encode.replace(/\+/g, '-').replace(/\//g, '_');
}

export function urlSafeDecode(encodeStr) {
  return encodeStr.replace(/-/g, '+').replace(/_/g, '/');
}
