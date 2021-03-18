const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('tape');
const crypto = require('crypto');
const ssbKeys = require('ssb-keys');
const SecretStack = require('secret-stack');
const caps = require('ssb-caps');
const pull = require('pull-stream');
const debug = require('debug')('test');

const ALICE_KEYS = ssbKeys.generate();
const ALICE_ID = ALICE_KEYS.id;
const ROOM_KEYS = ssbKeys.generate();
const ROOM_ID = ROOM_KEYS.id;
const ROOM_MSADDR = 'net:something.com:8008~shs:' + ROOM_ID.slice(1, -8);
const carlaKeys = ssbKeys.generate();

debug('alice is ' + ALICE_ID);
debug('room is ' + ROOM_ID);

let testInstance = 0;
const CreateSSB = (makeMockConn) => {
  const name = `test${testInstance}`;
  testInstance++;
  let sbot;

  const close = (cb) => {
    sbot.close(cb);
  };

  sbot = SecretStack({appKey: caps.shs})
    .use(require('./mock-conn'))
    .use(require('../lib/index'))
    .call(null, {
      path: fs.mkdtempSync(
        path.join(os.tmpdir(), 'ssb-http-auth-client-' + name),
      ),
      temp: true,
      name,
      keys: ALICE_KEYS,
      connections: {
        incoming: {
          tunnel: [{scope: 'public', transform: 'shs'}],
        },
        outgoing: {
          tunnel: [{transform: 'shs'}],
        },
      },
      mockConn: makeMockConn ? makeMockConn(close) : null,
    });

  return sbot;
};

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

test('httpAuthClient.consumeSignInSsbUri', (t) => {
  const cid = ALICE_ID
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
            t.equal(_sc, sc, 'sc matches')
            t.equal(Buffer.from(_cc, 'base64').length, 32, 'cc is 256 bits');
            const body = `=http-auth-sign-in:${cid}:${sid}:${_cc}:${_sc}`;
            t.true(ssbKeys.verify(ALICE_KEYS, _cr, body), 'cr is correct')
            done(null, true)
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

test.skip('when connected to a non-room, does not call tunnel.endpoints', (t) => {
  CreateSSB((close) => ({
    hub: () => ({
      listen: () =>
        pull.values([
          {
            type: 'connected',
            address: 'net:something.com:8008~noauth',
            key: ROOM_KEYS.id,
            details: {
              rpc: {
                tunnel: {
                  isRoom: (cb) => {
                    t.pass('rpc.tunnel.isRoom got called');
                    cb(null, false);
                    setTimeout(() => {
                      t.pass('did not call rpc.tunnel.endpoints');
                      close(t.end);
                    }, 200);
                  },
                  endpoints: () => {
                    t.fail('should not call rpc.tunnel.endpoints');
                    return pull.empty();
                  },
                },
              },
            },
          },
        ]),
    }),
  }));
});
