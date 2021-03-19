# ssb-http-auth-client

Plugin that implements [Sign-in with SSB](https://ssb-ngi-pointer.github.io/rooms2/#sign-in-with-ssb) (primarily to the web dashboard of SSB servers, such as rooms and others) on the client-side. This is supposed to be installed and used on **apps** that make remote calls to servers, thus *clients*.

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

## Usage

In both of the cases below, calling these muxrpc APIs is equivalent to **authorizing** the sign-in to complete. Other calls happen automatically in the background to complete the sign-in process.

- `httpAuthClient.produceSignInWebUrl(serverId, cb)`
   - Call this muxrpc API when you want your application to produce a login URL on the web interface on the server which owns the SSB ID `serverId`. The response is a web URL which you can use to redirect your app to the operating system's default browser.
- `httpAuthClient.consumeSignInSsbUri(ssbUri, cb)`
   - According to the *Sign-in with SSB* spec, it may in some cases produce an SSB URI on the server's web page of the format `ssb:experimental?action=start-http-auth....`. You should call this muxrpc API and provide the `ssbUri` to authorize `ssb-http-auth-client` to complete the sign-in process.

## License

LGPL-3.0
