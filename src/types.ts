// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: LGPL-3.0-only

import {FeedId} from 'ssb-typescript';
import {CONN} from 'ssb-conn/lib/conn';

export interface CB<T> {
  (err: any, val?: T): void;
}

export interface SSB {
  id: FeedId;
  close?: {
    hook: CallableFunction;
  };
  conn?: CONN;
  httpAuthClientTokens: {
    create(): string;
    has(cc: string): boolean;
  };
}

export type ParsedAddress = {host: string; port: number};

export type SSBWithConn = SSB & Required<Pick<SSB, 'conn'>>;

export interface Config {
  keys: {
    curve: string;
    public: string;
    private: string;
    id: FeedId;
  };
}
