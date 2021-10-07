// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: LGPL-3.0-only

import crypto = require('crypto');
import {Config, SSB} from './types';
import {NONCE_LENGTH_BYTE} from './constants';

/**
 * Constant (in milliseconds) for how frequent should the periodic check of
 * expired tokens be.
 */
const PERIOD = 20e3;

/**
 * Constant (in milliseconds) for the maximum age a token can take before it is
 * considered expired.
 */
const EXPIRY = 2 * 60e3;

module.exports = {
  name: 'httpAuthClientTokens',
  version: '1.0.0',
  manifest: {
    create: 'sync',
    has: 'sync',
  },
  permissions: {
    anonymous: {},
  },
  init(ssb: SSB, _config: Config) {
    const tokens = new Map<string /* cc */, number /* creation timestamp */>();
    let interval: NodeJS.Timeout | null = null;

    /**
     * Periodically invalidate old tokens
     */
    function startInterval() {
      if (interval) return; // it is already running
      interval = setInterval(() => {
        const expired: Array<string> = [];
        const now = Date.now();
        tokens.forEach((birth, cc) => {
          if (now > birth + EXPIRY) expired.push(cc);
        });
        for (const cc of expired) tokens.delete(cc);
        if (tokens.size === 0) stopInterval();
      }, PERIOD);
      interval.unref?.();
    }

    function stopInterval() {
      if (!interval) return; // it has already stopped
      clearInterval(interval);
    }

    // Close timer when ssb closes
    ssb.close?.hook(function (this: any, fn: any, args: any) {
      stopInterval();
      fn.apply(this, args);
    });

    return {
      create() {
        const nonce = crypto.randomBytes(NONCE_LENGTH_BYTE);
        const cc = nonce.toString('base64');
        tokens.set(cc, Date.now());
        startInterval();
        return cc;
      },

      has(cc: string) {
        return tokens.has(cc);
      },
    };
  },
};
