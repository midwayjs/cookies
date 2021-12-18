# Midway Cookies

Extends [pillarjs/cookies](https://github.com/pillarjs/cookies) to adapt koa and egg with some additional features.

## Encrypt

@midwayjs/cookies provide an alternative `encrypt` mode like `signed`. An encrypt cookie's value will be encrypted base on keys. Anyone who don't have the keys are unable to know the original cookie's value.

```ts
import * as Cookies from '@midwayjs/cookies');

const cookies = new Cookies(ctx, keys[, defaultCookieOptions]);

cookies.set('foo', 'bar', { encrypt: true });
cookies.get('foo', { encrypt: true });
```

**Note: you should both indicating in get and set in pairs.**

## Cookie Length Check

[Browsers all had some limitation in cookie's length](http://browsercookielimits.squawky.net/), so if set a cookie with an extremely long value(> 4093), egg-cookies will emit an `cookieLimitExceed` event. You can listen to this event and record.

```ts
import * as Cookies from '@midwayjs/cookies');

const cookies = new Cookies(ctx, keys);

cookies.on('cookieLimitExceed', { name, value } => {
  // log
});

cookies.set('foo', longText);
```

## License

[MIT]((http://github.com/midwayjs/cookies/blob/master/LICENSE))
