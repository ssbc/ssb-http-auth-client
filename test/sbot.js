// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: Unlicense

const fs = require('fs');
const os = require('os');
const path = require('path');
const SecretStack = require('secret-stack');
const caps = require('ssb-caps');
const {ALICE_KEYS} = require('./keys');

let testInstance = 0;

module.exports = (makeMockConn) => {
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
