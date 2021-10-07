// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: Unlicense

const test = require('tape');
const crypto = require('crypto');
const ssbKeys = require('ssb-keys');
const {ALICE_ID, ALICE_KEYS, ROOM_ID, ROOM_MSADDR} = require('./keys');
const CreateSSB = require('./sbot');

test('httpAuthClient.produceSignInWebUrl', (t) => {
  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersConnected() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),
  }));

  ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err, url) => {
    t.error(err, 'no error');
    t.equal(typeof url, 'string', 'url is string');
    t.pass(url);
    t.true(
      url.startsWith(
        `https://something.com/login?ssb-http-auth=1&cid=${encodeURIComponent(ALICE_ID)}`,
      ),
      'most of the url looks ok',
    );
    const cc = new URL(url).searchParams.get('cc');
    t.ok(cc, 'has cc query');
    t.equal(Buffer.from(cc, 'base64').length, 32, 'cc is 256 bits');
    ssb.close(t.end);
  });
});

test('httpAuthClient.produceSignInWebUrl twice', (t) => {
  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersConnected() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),
  }));

  ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err, url) => {
    t.error(err, 'no error');
    ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err2, url2) => {
      t.error(err2, 'no error');
      ssb.close(t.end);
    });
  });
});

test('httpAuthClient.consumeSignInSsbUri', (t) => {
  const cid = ALICE_ID;
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
            t.equal(_sc, sc, 'sc matches');
            t.equal(Buffer.from(_cc, 'base64').length, 32, 'cc is 256 bits');
            const body = `=http-auth-sign-in:${sid}:${cid}:${_sc}:${_cc}`;
            t.true(ssbKeys.verify(ALICE_KEYS, _sol, body), 'sol is correct');
            done(null, true);
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
    t.error(err, 'no error');
    t.true(answer, 'sign-in done with true');
    ssb.close(t.end);
  });
});

test('httpAuthClient.consumeSignInSsbUri alt', (t) => {
  const cid = ALICE_ID;
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
            t.equal(_sc, sc, 'sc matches');
            t.equal(Buffer.from(_cc, 'base64').length, 32, 'cc is 256 bits');
            const body = `=http-auth-sign-in:${sid}:${cid}:${_sc}:${_cc}`;
            t.true(ssbKeys.verify(ALICE_KEYS, _sol, body), 'sol is correct');
            done(null, true);
          },
        },
      };
      cb(null, rpc);
    },
  }));

  const uri =
    'ssb://experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.error(err, 'no error');
    t.true(answer, 'sign-in done with true');
    ssb.close(t.end);
  });
});

test('httpAuthClient.consumeSignInSsbUri with multiserverAddress', (t) => {
  const cid = ALICE_ID;
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll() {
        return [];
      },
    }),

    connect: (addr, cb) => {
      t.equal(addr, ROOM_MSADDR, 'connected to correct server');
      const rpc = {
        httpAuth: {
          sendSolution(_sc, _cc, _sol, done) {
            t.equal(_sc, sc, 'sc matches');
            t.equal(Buffer.from(_cc, 'base64').length, 32, 'cc is 256 bits');
            const body = `=http-auth-sign-in:${sid}:${cid}:${_sc}:${_cc}`;
            t.true(ssbKeys.verify(ALICE_KEYS, _sol, body), 'sol is correct');
            done(null, true);
          },
        },
      };
      cb(null, rpc);
    },
  }));

  const uri =
    'ssb://experimental?' +
    [
      'action=start-http-auth',
      'sid=' + encodeURIComponent(sid),
      'sc=' + encodeURIComponent(sc),
      'multiserverAddress=' + encodeURIComponent(ROOM_MSADDR),
    ].join('&');

  ssb.httpAuthClient.consumeSignInSsbUri(uri, (err, answer) => {
    t.error(err, 'no error');
    t.true(answer, 'sign-in done with true');
    ssb.close(t.end);
  });
});

test('httpAuthClient.invalidateAllSessions', (t) => {
  const sid = ROOM_ID;
  const sc = crypto.randomBytes(32).toString('base64');

  let connectedToRoom = false;
  let invalidated = false;

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersAll() {
        t.false(connectedToRoom);
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
      peersConnected() {
        t.true(connectedToRoom);
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),

    connect: (addr, cb) => {
      t.equal(addr, ROOM_MSADDR, 'connected to correct server');
      const rpc = {
        httpAuth: {
          sendSolution(_sc, _cc, _sol, done) {
            done(null, true);
          },

          invalidateAllSolutions(done) {
            invalidated = true;
            done(null, true);
          },
        },
      };
      connectedToRoom = true;
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
    t.error(err, 'no error');
    t.true(answer, 'sign-in done with true');
    t.false(invalidated);

    ssb.httpAuthClient.invalidateAllSessions(ROOM_ID, (err2, answer2) => {
      t.error(err2, 'no error');
      t.true(invalidated);
      t.true(answer2);

      ssb.close(t.end);
    });
  });
});

test('httpAuth.requestSolution', (t) => {
  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersConnected() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),
  }));

  ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err, url) => {
    const cc = new URL(url).searchParams.get('cc');
    const cid = ALICE_ID;
    const sid = ROOM_ID;
    const sc = crypto.randomBytes(32).toString('base64');
    ssb.httpAuth.requestSolution.call({id: sid}, sc, cc, (err2, sol) => {
      t.error(err2, 'no error');
      const body = `=http-auth-sign-in:${sid}:${cid}:${sc}:${cc}`;
      t.true(ssbKeys.verify(ALICE_KEYS, sol, body), 'sol is correct');
      ssb.close(t.end);
    });
  });
});

test.skip('httpAuthClient.produceSignInWebUrl clears old tokens', (t) => {
  t.timeoutAfter(4 * 60e3);

  const ssb = CreateSSB((close) => ({
    query: () => ({
      peersConnected() {
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),
  }));

  ssb.httpAuthClient.produceSignInWebUrl(ROOM_ID, (err, url) => {
    t.error(err, 'no error');
    const cc = new URL(url).searchParams.get('cc');
    t.true(ssb.httpAuthClientTokens.has(cc), 'has token');
    setTimeout(() => {
      t.false(ssb.httpAuthClientTokens.has(cc), 'has no token');
      ssb.close(t.end);
    }, 3 * 60e3);
  });
});
