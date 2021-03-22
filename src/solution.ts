import { FeedId } from "ssb-typescript";
const ssbKeys = require('ssb-keys');

export function solve(
  keys: any,
  sid: FeedId,
  cid: FeedId,
  sc: string,
  cc: string,
): string {
  const body = `=http-auth-sign-in:${sid}:${cid}:${sc}:${cc}`;
  const sol = ssbKeys.sign(keys, body);
  return sol;
}
