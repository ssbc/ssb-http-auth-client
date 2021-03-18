# ssb-http-auth-client

TODO TODO TODO TODO TODO TODO TODO TODO TODO

## Installation

**Prerequisites:**

- Node.js 6.5.0 or higher
- Requires `secret-stack@>=6.2.0`
- Requires `ssb-keys@>=8.1.0`
- [ssb-conn](https://github.com/staltz/ssb-conn) installed as a secret-stack plugin

```
npm install --save ssb-http-auth-client
```

Require and use the following plugin into your ssb-server or secret-stack setup:

```diff
 SecretStack({appKey: require('ssb-caps').shs})
   .use(require('ssb-master'))
   .use(require('ssb-logging'))
   .use(require('ssb-conn'))
   .use(require('ssb-replicate'))
   .use(require('ssb-ebt'))
+  .use(require('ssb-http-auth-client'))
   .use(require('ssb-friends'))
   .use(require('ssb-about'))
   .call(null, require('./config'));
```

TODO TODO TODO TODO TODO TODO TODO TODO

## Usage

TODO TODO TODO TODO TODO TODO TODO TODO

## License

LGPL-3.0
