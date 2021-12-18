export interface CookieOptions {
  path?: string;
  domain?: string;
  sameSite?: boolean | 0 | string;
  expires?: Date;
  maxAge?: number;
  secure?: boolean;
  httpOnly?: boolean;
}

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
   * The path for the cookie to be set in
   */
  path?: string;
  /**
   * The domain for the cookie
   */
  domain?: string;
  /**
   * Is overridable
   */
  overwrite?: boolean;
  /**
   * Is the same site
   */
  sameSite?: boolean | string;
  /**
   * Encrypt the cookie's value or not
   */
  encrypt?: boolean;
  /**
   * Max age for browsers
   */
  maxAge?: number;
  /**
   * Expire time
   */
  expires?: Date;
  /**
  * Is for http only
  */
  httpOnly?: boolean;
  /**
  * Encrypt the cookie's value or not
  */
  secure?: boolean;
  /**
   * Is it signed or not.
   */
  signed?: boolean;
}
