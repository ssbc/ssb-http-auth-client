// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: LGPL-3.0-only

import {FeedId} from 'ssb-typescript';
const debug = require('debug')('ssb:http-auth:client');
import {CB, Config, SSB} from './types';
import {NONCE_LENGTH, NONCE_LENGTH_BASE64} from './constants';
import {solve} from './solution';

/**
 * Don't leak the local stack trace to the remote peer.
 */
function stacklessError(message: string) {
  const error = new Error(message);
  error.stack = '';
  return error;
}

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
        cb(stacklessError('httpAuth.sendSolution not supported on the client side')); // prettier-ignore
      },

      requestSolution(sc: string, cc: string, cb: CB<string>) {
        if (sc.length < NONCE_LENGTH_BASE64) {
          cb(stacklessError(`Server nonce "sc" is not ${NONCE_LENGTH} bits: ${sc}`)); // prettier-ignore
          return;
        }
        if (cc.length < NONCE_LENGTH_BASE64) {
          cb(stacklessError(`Client nonce "cc" is not ${NONCE_LENGTH} bits: ${cc}`)); // prettier-ignore
          return;
        }
        if (!ssb.httpAuthClientTokens.has(cc)) {
          cb(stacklessError('The client nonce "cc" is unknown or has expired')); // prettier-ignore
          return;
        }
        const cid: FeedId = ssb.id;
        const sid: FeedId = (this as any).id;
        debug(`requestSolution where sid=${sid}, cid=${cid}, sc=${sc}, cc=${cc}`); // prettier-ignore
        const sol = solve(config.keys, sid, cid, sc, cc);
        cb(null, sol);
      },

      invalidateAllSolutions(cb: CB<never>) {
        cb(stacklessError('httpAuth.invalidateAllSolutions not supported on the client side')); // prettier-ignore
      },
    };
  },
};
