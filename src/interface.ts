export interface CookieGetOptions {
  /**
   * Whether to sign or not (The default value is true).
   */
  signed?: boolean;
  /**
   * Encrypt the cookie's value or not (The default value is false).
   */
  encrypt?: boolean;
}

export interface CookieSetOptions {
  /**
   * a string indicating the path of the cookie (/ by default).
   */
  path?: string | null;
  /**
   * a string indicating the domain of the cookie (no default).
   */
  domain?: string;
  /**
   * a boolean indicating whether to overwrite previously set
   * cookies of the same name (false by default). If this is true,
   * all cookies set during the same request with the same
   * name (regardless of path or domain) are filtered out of
   * the Set-Cookie header when setting this cookie.
   */
  overwrite?: boolean;
  /**
   * a boolean or string indicating whether the cookie is a "same site" cookie (false by default).
   * This can be set to 'strict', 'lax', or true (which maps to 'strict').
   */
  sameSite?: 'strict' | 'lax' | 'none' | boolean;
  /**
   * Encrypt the cookie's value or not
   */
  encrypt?: boolean;
  /**
   * a number representing the milliseconds from Date.now() for expiry
   */
  maxAge?: number;
  /**
   * a Date object indicating the cookie's expiration
   * date (expires at the end of session by default).
   */
  expires?: Date;
  /**
   * a boolean indicating whether the cookie is only to be sent over HTTP(S),
   * and not made available to client JavaScript (true by default).
   */
  httpOnly?: boolean;
  /**
   * a boolean indicating whether the cookie is only to be sent
   * over HTTPS (false by default for HTTP, true by default for HTTPS).
   */
  secure?: boolean;
  /**
   * a boolean indicating whether the cookie is to be signed (false by default).
   * If this is true, another cookie of the same name with the .sig suffix
   * appended will also be sent, with a 27-byte url-safe base64 SHA1 value
   * representing the hash of cookie-name=cookie-value against the first Keygrip key.
   * This signature key is used to detect tampering the next time a cookie is received.
   */
  signed?: boolean;
  /**
   * a string indicating the cookie priority. This can be set to 'low', 'medium', or 'high'.
   * only supported in chrome 81+.
   * https://developer.chrome.com/blog/new-in-devtools-81?hl=zh-cn#cookiepriority
   */
  priority?: 'Low' | 'Medium' | 'High';
  /**
   * a boolean indicating whether to partition the cookie in Chrome for the CHIPS Update，false by default.
   * If this is true, Cookies from embedded sites will be partitioned and only readable from the same top level site from which it was created.
   */
  partitioned?: boolean;
  /**
   * Remove unpartitioned same name cookie or not.
   */
  removeUnpartitioned?: boolean;
}
