import * as assert from 'assert';
import { Cookie } from './cookie';
import { CookieGetOptions, CookieSetOptions } from './interface';
import { Keygrip } from './keygrip';
import { isSameSiteNoneCompatible as _isSameSiteNoneCompatible } from 'should-send-same-site-none';
import { IncomingMessage, ServerResponse } from 'http';

const KEYS_ARRAY = Symbol('midwayCookies:keysArray');
const KEYS = Symbol('midwayCookies:keys');
const keyCache = new Map();

/**
 * cookies extend pillarjs/cookies, add encrypt and decrypt
 */
export class Cookies {
  private readonly _defaultCookieOptions: CookieSetOptions;
  private readonly _defaultGetCookieOptions: CookieGetOptions;
  private uaParseResult: { chromium: boolean; majorVersion: number };
  public ctx;
  public secure;
  public app;
  public request: IncomingMessage;
  public response: ServerResponse;

  constructor(
    ctx,
    keys,
    defaultCookieOptions?: CookieSetOptions,
    defaultGetCookieOptions?: CookieGetOptions
  ) {
    this[KEYS_ARRAY] = keys ? [].concat(keys) : keys;
    // default cookie options
    this._defaultCookieOptions = defaultCookieOptions;
    // default get cookie options
    this._defaultGetCookieOptions = defaultGetCookieOptions;
    this.ctx = ctx;
    this.secure = defaultCookieOptions?.secure ?? this.ctx.secure;
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
    opts = Object.assign({}, this._defaultGetCookieOptions || {}, opts);
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
    if (res?.value) {
      return res.value.toString();
    }
    return undefined;
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
  public set(name: string, value: string | null, opts?: CookieSetOptions): this;
  public set(name: string, opts?: CookieSetOptions): this;
  public set(name: string, value?: any, opts?: CookieSetOptions): this {
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
    const userAgent = this.ctx.get('user-agent');
    if (
      opts.sameSite &&
      typeof opts.sameSite === 'string' &&
      opts.sameSite.toLowerCase() === 'none'
    ) {
      if (
        !this.secure ||
        (userAgent && !this.isSameSiteNoneCompatible(userAgent))
      ) {
        // Non-secure context or Incompatible clients, don't send SameSite=None property
        opts.sameSite = false;
      }
    }

    if (opts.partitioned) {
      if (
        !this.secure ||
        !userAgent ||
        (userAgent && !this.isPartitionedCompatible(userAgent))
      ) {
        // ignore partitioned when not secure or incompatible clients
        opts.partitioned = false;
      }
    }

    // remove unpartitioned same name cookie first
    if (opts.partitioned && opts.removeUnpartitioned) {
      const overwrite = opts.overwrite;
      if (overwrite) {
        opts.overwrite = false;
        headers = ignoreCookiesByName(headers, name);
      }
      const removeCookieOpts = Object.assign({}, opts, {
        partitioned: false,
      });
      const removeUnpartitionedCookie = new Cookie(name, '', removeCookieOpts);
      // if user not set secure, reset secure to ctx.secure
      if (opts.secure === undefined)
        removeUnpartitionedCookie.attrs.secure = this.secure;

      headers = pushCookie(headers, removeUnpartitionedCookie);
      // signed
      if (signed) {
        removeUnpartitionedCookie.name += '.sig';
        headers = ignoreCookiesByName(headers, removeUnpartitionedCookie.name);
        headers = pushCookie(headers, removeUnpartitionedCookie);
      }
    }

    if (opts.priority) {
      if (!userAgent || (userAgent && !this.isPriorityCompatible(userAgent))) {
        // ignore priority when not secure or incompatible clients
        opts.priority = undefined;
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

  protected isSameSiteNoneCompatible(userAgent: string) {
    // Chrome >= 80.0.0.0
    const result = this.parseChromiumAndMajorVersion(userAgent);
    if (result.chromium && result.majorVersion) {
      return result.majorVersion >= 80;
    }
    return _isSameSiteNoneCompatible(userAgent);
  }

  protected isPartitionedCompatible(userAgent: string) {
    // Chrome & Edge >= 114.0.0.0
    // https://developers.google.com/privacy-sandbox/3pcd/chips
    const result = this.parseChromiumAndMajorVersion(userAgent);
    if (result.chromium && result.majorVersion) {
      return result.majorVersion >= 114;
    }
    return false;
  }

  protected parseChromiumAndMajorVersion(userAgent): {
    chromium: boolean;
    majorVersion: number;
  } {
    // https://github.com/linsight/should-send-same-site-none/blob/master/index.js#L86
    if (!this.uaParseResult) {
      const m = /Chrom[^ /]+\/(\d+)[.\d]* /.exec(userAgent);
      if (!m) return { chromium: false, majorVersion: undefined };
      // Extract digits from first capturing group.
      this.uaParseResult = { chromium: true, majorVersion: parseInt(m[1]) };
    }

    return this.uaParseResult;
  }

  protected isPriorityCompatible(userAgent: string) {
    // Chrome >= 81.0.0.0
    // https://developer.chrome.com/blog/new-in-devtools-81?hl=zh-cn#cookiepriority
    const result = this.parseChromiumAndMajorVersion(userAgent);
    if (result.chromium && result.majorVersion) {
      return result.majorVersion >= 81;
    }
    return false;
  }
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
    cookies = ignoreCookiesByName(cookies, cookie.name);
  }
  cookies.push(cookie.toHeader());
  return cookies;
}

function ignoreCookiesByName(cookies, name) {
  const prefix = `${name}=`;
  return cookies.filter(c => !c.startsWith(prefix));
}

export function urlSafeEncode(encode: string): string {
  return encode.replace(/\+/g, '-').replace(/\//g, '_');
}

export function urlSafeDecode(encodeStr) {
  return encodeStr.replace(/-/g, '+').replace(/_/g, '/');
}
