// SPDX-FileCopyrightText: 2021 Andre Staltz
//
// SPDX-License-Identifier: LGPL-3.0-only

/**
 * Length of the nonces in bits.
 */
export const NONCE_LENGTH = 256;

/**
 * Length of the nonces in bytes.
 */
export const NONCE_LENGTH_BYTE = NONCE_LENGTH / 8;

/**
 * Length of the nonces in the size of the base64 string.
 */
export const NONCE_LENGTH_BASE64 = Math.ceil(NONCE_LENGTH / 6);
