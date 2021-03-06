// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: LGPL-3.0-only

import {FeedId} from 'ssb-typescript';
const Ref = require('ssb-ref');
const debug = require('debug')('ssb:http-auth:client');
import {CB, Config, ParsedAddress, SSB, SSBWithConn} from './types';
import {NONCE_LENGTH_BASE64} from './constants';
import {solve} from './solution';

function hasConnInstalled(ssb: SSB): ssb is SSBWithConn {
  return !!ssb.conn?.connect;
}

module.exports = {
  name: 'httpAuthClient',
  version: '1.0.0',
  manifest: {
    produceSignInWebUrl: 'async',
    consumeSignInSsbUri: 'async',
    invalidateAllSessions: 'async',
  },
  permissions: {
    anonymous: {},
  },
  init(ssb: SSB, config: Config) {
    if (!hasConnInstalled(ssb)) {
      throw new Error('ssb-http-auth-client requires the ssb-conn plugin');
    }

    return {
      produceSignInWebUrl(sid: FeedId, cb: CB<string>) {
        if (!Ref.isFeed(sid)) {
          cb(new Error('Invalid SSB ID ' + sid));
          return;
        }

        // Check if server is online
        const peer = ssb.conn
          .query()
          .peersConnected()
          .find(([, data]) => data.key === sid);
        if (!peer) {
          cb(new Error('Cannot sign-in to disconnected server ' + sid));
          return;
        }

        // Pick host from server
        const [addr] = peer;
        const parsed = Ref.toAddress(addr) as ParsedAddress | false;
        if (!parsed) {
          cb(new Error(`Cannot sign-in to server with bad address ${addr}`));
          return;
        }
        const {host} = parsed;

        // Build the URL
        const cid: FeedId = ssb.id;
        const cc = ssb.httpAuthClientTokens.create();
        const _cid = encodeURIComponent(cid);
        const _cc = encodeURIComponent(cc);
        const url = `https://${host}/login?ssb-http-auth=1&cid=${_cid}&cc=${_cc}`;

        cb(null, url);
      },

      consumeSignInSsbUri(uri: string, cb: CB<boolean>) {
        // Parse URI
        let u: URL;
        try {
          u = new URL(uri);
        } catch (err) {
          cb(new Error('Invalid SSB URI provided: ' + uri));
          return;
        }
        if (u.protocol !== 'ssb:') {
          cb(new Error('Invalid SSB URI provided: ' + uri));
          return;
        }
        if (u.pathname !== 'experimental' && u.host !== 'experimental') {
          cb(new Error('Invalid experimental SSB URI provided: ' + uri));
          return;
        }
        if (u.searchParams.get('action') !== 'start-http-auth') {
          cb(new Error('SSB URI is unrelated to httpAuth: ' + uri));
          return;
        }

        // Pick `sid` query
        const sid = u.searchParams.get('sid')!;
        if (!Ref.isFeed(sid)) {
          cb(new Error('Invalid "sid" query in SSB URI: ' + uri));
          return;
        }

        // Pick `sc` query
        const sc = u.searchParams.get('sc');
        if (!sc) {
          cb(new Error('Invalid "sc" query in SSB URI: ' + uri));
          return;
        }
        if (sc.length < NONCE_LENGTH_BASE64) {
          cb(new Error('Server nonce "sc" is less than 256 bits: ' + sc));
          return;
        }

        // Discover the server's multiserverAddress
        let serverMSAddr: string = u.searchParams.get('multiserverAddress')!;
        if (!serverMSAddr || !Ref.toAddress(serverMSAddr)) {
          const peer = ssb.conn
            .query()
            .peersAll()
            .find(([, data]) => data.key === sid);
          if (!peer) {
            cb(new Error('Cannot sign-in to unknown server ' + sid));
            return;
          }
          [serverMSAddr] = peer;
        }

        // Solve challenges
        const cc = ssb.httpAuthClientTokens.create();
        const cid: FeedId = ssb.id;
        const sol = solve(config.keys, sid, cid, sc, cc);
        debug(`sendSolution where sid=${sid}, cid=${cid}, sc=${sc}, cc=${cc}`);

        // Connect to server
        ssb.conn.connect(serverMSAddr, (err, rpc) => {
          if (err) {
            cb(new Error(`Cannot sign-in to server ${sid} because: ${err}`));
            return;
          }
          if (!rpc) {
            cb(new Error(`Cannot sign-in to server ${sid}, it seems offline`));
            return;
          }

          // Sign-in
          rpc.httpAuth.sendSolution(sc, cc, sol, (err2: any, answer: any) => {
            if (err2) {
              cb(new Error(`httpAuth.sendSolution at ${sid} failed: ${err2}`));
              return;
            }
            debug(
              `Server ${sid} answered our httpAuth.sendSolution with ${answer}`,
            );
            cb(null, answer);
          });
        });
      },

      invalidateAllSessions(sid: FeedId, cb: CB<string>) {
        if (!Ref.isFeed(sid)) {
          cb(new Error('Invalid SSB ID ' + sid));
          return;
        }

        // Check if server is online
        const peer = ssb.conn
          .query()
          .peersConnected()
          .find(([, data]) => data.key === sid);
        if (!peer) {
          cb(new Error('Cannot sign-out from disconnected server ' + sid));
          return;
        }

        // Sign-out
        const [addr] = peer;
        ssb.conn.connect(addr, (err, rpc) => {
          if (err) {
            cb(new Error(`Cannot sign-out from server ${sid} because: ${err}`));
            return;
          }
          if (!rpc) {
            cb(new Error(`Cannot sign-out from ${sid}, it seems offline`));
            return;
          }

          rpc.httpAuth.invalidateAllSolutions((err2: any, answer: any) => {
            if (err2) {
              cb(new Error(`sign-out at ${sid} failed: ${err2}`));
              return;
            }
            debug(
              `Server ${sid} answered our ` +
                `httpAuth.invalidateAllSolutions with ${answer}`,
            );
            cb(null, answer);
          });
        });
      },
    };
  },
};
