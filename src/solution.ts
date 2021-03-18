import { FeedId } from "ssb-typescript";
const ssbKeys = require('ssb-keys');

export function solve(
  keys: any,
  cid: FeedId,
  sid: FeedId,
  cc: string,
  sc: string,
): string {
  const body = `=http-auth-sign-in:${cid}:${sid}:${cc}:${sc}`;
  const cr = ssbKeys.sign(keys, body);
  return cr;
}
