// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: Unlicense

const test = require('tape');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const SecretStack = require('secret-stack');
const ssbKeys = require('ssb-keys');
const caps = require('ssb-caps');
const {ALICE_KEYS, ROOM_ID, ROOM_MSADDR, ALICE_ID} = require('./keys');
const CreateSSB = require('./sbot');

test('error if ssb-conn is missing', (t) => {
  t.throws(() => {
    SecretStack({appKey: caps.shs})
      .use(require('../lib/index'))
      .call(null, {
        path: fs.mkdtempSync(
          path.join(os.tmpdir(), 'ssb-http-auth-client-conn-missing'),
        ),
        temp: true,
        name: 'ssb-http-auth-client-conn-missing',
        keys: ALICE_KEYS,
        connections: {
          incoming: {
            tunnel: [{scope: 'public', transform: 'shs'}],
          },
          outgoing: {
            tunnel: [{transform: 'shs'}],
          },
        },
      });
  }, 'ssb-http-auth-client requires the ssb-conn plugin');

  t.end();
});

test('error httpAuthClient.produceSignInWebUrl when sid is bad', (t) => {
  const ssb = CreateSSB((close) => ({}));

  ssb.httpAuthClient.produceSignInWebUrl('foobarbaz', (err, url) => {
    t.ok(err, 'has error');
    t.match(err.message, /Invalid SSB ID/);
    t.notOk(url);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.produceSignInWebUrl when server is offline', (t) => {
  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersConnected() {
        return [];
      },
    }),
  }));

  ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err, url) => {
    t.ok(err, 'has error');
    t.match(err.message, /Cannot sign-in to disconnected server/);
    t.notOk(url);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.produceSignInWebUrl if server has no host', (t) => {
  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersConnected() {
        return [['~http://example.com', {key: ROOM_ID}]];
      },
    }),
  }));

  ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err, url) => {
    t.ok(err, 'has error');
    t.match(err.message, /Cannot sign-in to server with bad address/);
    t.notOk(url);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when server is unknown', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll(pool) {
        return [];
      },
    }),
  }));

  const uri =
    'ssb:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Cannot sign-in to unknown server/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when server is offline', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),

    connect: (addr, cb) => {
      cb(new Error('testing failure to connect'));
    },
  }));

  const uri =
    'ssb:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /testing failure to connect/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when server is offline', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),

    connect: (addr, cb) => {
      cb(null, false);
    },
  }));

  const uri =
    'ssb:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Cannot sign-in to server [^,]+, it seems offline/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri if sendSolution fails', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),

    connect: (addr, cb) => {
      t.equal(addr, ROOM_MSADDR, 'connected to correct server');
      const rpc = {
        httpAuth: {
          sendSolution(_sc, _cc, _sol, done) {
            done(new Error('testing failure to httpAuth.sendSolution'));
          },
        },
      };
      cb(null, rpc);
    },
  }));

  const uri =
    'ssb:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /testing failure to httpAuth\.sendSolution/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI is missing', (t) => {
  const ssb = CreateSSB((close) => ({}));

  ssb.httpAuthClient.consumeSignInSsbUri('', (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Invalid SSB URI provided/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI is not SSB', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({}));

  const uri =
    'scuttlebutt:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Invalid SSB URI provided/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when server is offline', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),

    connect: (addr, cb) => {
      cb(new Error('testing failure to connect'));
    },
  }));

  const uri =
    'ssb:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /testing failure to connect/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI is not experi', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({}));

  const uri =
    'ssb:?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Invalid experimental SSB URI provided/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI misses action', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({}));

  const uri =
    'ssb:experimental?' +
    ['sid=' + encodeURIComponent(sid), 'sc=' + encodeURIComponent(sc)].join(
      '&',
    );

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /SSB URI is unrelated to httpAuth/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI misses sid', (t) => {
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({}));

  const uri =
    'ssb:experimental?' +
    ['action=start-http-auth', 'sc=' + encodeURIComponent(sc)].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Invalid "sid" query in SSB URI/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI misses sc', (t) => {
  const sid = ROOM_ID;

  const ssb = CreateSSB((close) => ({}));

  const uri =
    'ssb:experimental?' +
    ['action=start-http-auth', 'sid=' + encodeURIComponent(sid)].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Invalid "sc" query in SSB URI/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuthClient.consumeSignInSsbUri when URI sc is short', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(16).toString('base64');

  const ssb = CreateSSB((close) => ({}));

  const uri =
    'ssb:experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.ok(err, 'has error');
    t.match(err.message, /Server nonce "sc" is less than 256 bits/);
    t.notOk(answer);
    ssb.close(t.end);
  });
});

test('error httpAuth.requestSolution when missing cc', (t) => {
  const ssb = CreateSSB((close) => ({}));

  const sid = ROOM_ID;
  const cc = crypto.randomBytes(32).toString('base64');
  const sc = crypto.randomBytes(32).toString('base64');
  ssb.httpAuth.requestSolution.call({id: sid}, sc, cc, (err, sol) => {
    t.ok(err, 'has error');
    t.match(err.message, /The client nonce "cc" is unknown or has expired/);
    t.notOk(sol, 'no sol');
    ssb.close(t.end);
  });
});

test('error httpAuth.requestSolution when cc is short', (t) => {
  const ssb = CreateSSB((close) => ({}));

  const sid = ROOM_ID;
  const cc = crypto.randomBytes(16).toString('base64');
  const sc = crypto.randomBytes(32).toString('base64');
  ssb.httpAuth.requestSolution.call({id: sid}, sc, cc, (err, sol) => {
    t.ok(err, 'has error');
    t.match(err.message, /Client nonce "cc" is not 256 bits/);
    t.notOk(sol, 'no sol');
    ssb.close(t.end);
  });
});

test('error httpAuth.requestSolution when sc is short', (t) => {
  const ssb = CreateSSB((close) => ({}));

  const sid = ROOM_ID;
  const cc = crypto.randomBytes(32).toString('base64');
  const sc = crypto.randomBytes(16).toString('base64');
  ssb.httpAuth.requestSolution.call({id: sid}, sc, cc, (err, sol) => {
    t.ok(err, 'has error');
    t.match(err.message, /Server nonce "sc" is not 256 bits/);
    t.notOk(sol, 'no sol');
    ssb.close(t.end);
  });
});

test('error httpAuth.sendSolution always', (t) => {
  const sid = ROOM_ID;
  const cid = ALICE_ID;
  const sc = crypto.randomBytes(32).toString('base64');
  const cc = crypto.randomBytes(32).toString('base64');
  const body = `=http-auth-sign-in:${sid}:${cid}:${sc}:${cc}`;
  const sol = ssbKeys.sign(ALICE_KEYS, body);

  const ssb = CreateSSB((close) => ({}));

  ssb.httpAuth.sendSolution(sc, cc, sol, (err, response) => {
    t.ok(err, 'has error');
    t.match(err.message, /httpAuth.sendSolution not supported/);
    t.notOk(response, 'no response');
    ssb.close(t.end);
  });
});

test('error httpAuth.invalidateAllSolutions always', (t) => {
  const ssb = CreateSSB((close) => ({}));

  ssb.httpAuth.invalidateAllSolutions((err, response) => {
    t.ok(err, 'has error');
    t.match(err.message, /httpAuth.invalidateAllSolutions not supported/);
    t.notOk(response, 'no response');
    ssb.close(t.end);
  });
});
