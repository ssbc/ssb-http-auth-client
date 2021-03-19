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
        `https://something.com/login?cid=${encodeURIComponent(ALICE_ID)}`,
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
      peersConnectable(pool) {
        t.equal(pool, 'dbAndStaging');
        return [[ROOM_MSADDR, {key: ROOM_ID}]];
      },
    }),

    connect: (addr, cb) => {
      t.equal(addr, ROOM_MSADDR, 'connected to correct server');
      const rpc = {
        httpAuth: {
          signIn(_sc, _cc, _cr, done) {
            t.equal(_sc, sc, 'sc matches');
            t.equal(Buffer.from(_cc, 'base64').length, 32, 'cc is 256 bits');
            const body = `=http-auth-sign-in:${cid}:${sid}:${_cc}:${_sc}`;
            t.true(ssbKeys.verify(ALICE_KEYS, _cr, body), 'cr is correct');
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

test('httpAuth.signIn', (t) => {
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
    ssb.httpAuth.signIn.call({id: sid}, sc, cc, null, (err2, cr) => {
      t.error(err2, 'no error');
      const body = `=http-auth-sign-in:${cid}:${sid}:${cc}:${sc}`;
      t.true(ssbKeys.verify(ALICE_KEYS, cr, body), 'cr is correct');
      ssb.close(t.end);
    });
  });
});

test('httpAuthClient.produceSignInWebUrl clears old tokens', (t) => {
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
