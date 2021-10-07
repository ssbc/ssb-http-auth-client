// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: LGPL-3.0-only

import {FeedId} from 'ssb-typescript';
const debug = require('debug')('ssb:http-auth:client');
import {CB, Config, SSB} from './types';
import {NONCE_LENGTH, NONCE_LENGTH_BASE64} from './constants';
import {solve} from './solution';

module.exports = {
  name: 'httpAuth',
  version: '1.0.0',
  manifest: {
    sendSolution: 'async',
    requestSolution: 'async',
    invalidateAllSolutions: 'async',
  },
  permissions: {
    anonymous: {
      allow: ['sendSolution', 'requestSolution', 'invalidateAllSolutions'],
    },
  },
  init(ssb: SSB, config: Config) {
    return {
      sendSolution(_sc: string, _cc: string, _sol: string, cb: CB<never>) {
        cb(new Error('httpAuth.sendSolution not supported on the client side'));
      },

      requestSolution(sc: string, cc: string, cb: CB<string>) {
        if (sc.length < NONCE_LENGTH_BASE64) {
          cb(new Error(`Server nonce "sc" is not ${NONCE_LENGTH} bits: ${sc}`));
          return;
        }
        if (cc.length < NONCE_LENGTH_BASE64) {
          cb(new Error(`Client nonce "cc" is not ${NONCE_LENGTH} bits: ${cc}`));
          return;
        }
        if (!ssb.httpAuthClientTokens.has(cc)) {
          cb(new Error('The client nonce "cc" is unknown or has expired'));
          return;
        }
        const cid: FeedId = ssb.id;
        const sid: FeedId = (this as any).id;
        debug(
          `requestSolution where sid=${sid}, cid=${cid}, sc=${sc}, cc=${cc}`,
        );
        const sol = solve(config.keys, sid, cid, sc, cc);
        cb(null, sol);
      },

      invalidateAllSolutions(cb: CB<never>) {
        cb(
          new Error(
            'httpAuth.invalidateAllSolutions not supported on the client side',
          ),
        );
      },
    };
  },
};
