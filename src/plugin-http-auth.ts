import {FeedId} from 'ssb-typescript';
const debug = require('debug')('ssb:http-auth:client');
import {CB, Config, SSB} from './types';
import {NONCE_LENGTH, NONCE_LENGTH_BASE64} from './constants';
import {solve} from './solution';

module.exports = {
  name: 'httpAuth',
  version: '1.0.0',
  manifest: {
    signIn: 'async',
    signOut: 'async',
  },
  permissions: {
    anonymous: {allow: ['signIn', 'signOut'], deny: null},
  },
  init(ssb: SSB, config: Config) {
    return {
      signIn(sc: string, cc: string, crInput: null, cb: CB<string>) {
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
        if (crInput !== null) {
          cb(new Error('Client-side httpAuth.signIn should not receive "cr"'));
          return;
        }
        const cid: FeedId = ssb.id;
        const sid: FeedId = (this as any).id;
        debug(`signIn with: cid=${cid}, sid=${sid}, cc=${cc}, sc=${sc}`);
        const cr = solve(config.keys, cid, sid, cc, sc);
        cb(null, cr);
      },

      signOut(cb: CB<never>) {
        cb(new Error('httpAuth.signOut not supported on the client side'));
      },
    };
  },
};
