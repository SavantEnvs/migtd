// Copyright 2015-2019 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use super::{format_output, sha1, sha2, Output};
use crate::{cpu, polyfill::slice};
use core::mem::size_of;

extern crate alloc;

// Invariant: When constructed with `new32` (resp. `new64`), `As32` (resp.
// `As64`) is the active variant.
// Invariant: The active variant never changes after initialization.
#[derive(Clone)]
pub(super) enum DynState {
    As64(sha2::State64),
    As32(sha2::State32),
}

impl DynState {
    pub const fn new32(initial_state: sha2::State32) -> Self {
        Self::As32(initial_state)
    }

    pub const fn new64(initial_state: sha2::State64) -> Self {
        Self::As64(initial_state)
    }

    pub fn format_output(self) -> Output {
        match self {
            Self::As64(state) => {
                format_output::<_, _, { size_of::<u64>() }>(state, u64::to_be_bytes)
            }
            Self::As32(state) => {
                format_output::<_, _, { size_of::<u32>() }>(state, u32::to_be_bytes)
            }
        }
    }

    /// Serialize the state to bytes.
    /// For State32: returns 32 bytes (8 * u32)
    /// For State64: returns 64 bytes (8 * u64)
    pub(super) fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        match self {
            Self::As32(state) => {
                let mut bytes = alloc::vec::Vec::with_capacity(32);
                for word in state.iter() {
                    bytes.extend_from_slice(&word.0.to_le_bytes());
                }
                bytes
            }
            Self::As64(state) => {
                let mut bytes = alloc::vec::Vec::with_capacity(64);
                for word in state.iter() {
                    bytes.extend_from_slice(&word.0.to_le_bytes());
                }
                bytes
            }
        }
    }

    /// Deserialize the state from bytes.
    /// For 32-byte input: creates State32
    /// For 64-byte input: creates State64
    pub(super) fn from_bytes(bytes: &[u8]) -> Result<Self, ()> {
        use core::num::Wrapping;

        match bytes.len() {
            32 => {
                let mut state = [Wrapping(0u32); 8];
                for (i, chunk) in bytes.chunks_exact(4).enumerate() {
                    if i >= 8 {
                        return Err(());
                    }
                    let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                    state[i] = Wrapping(word);
                }
                Ok(Self::As32(state))
            }
            64 => {
                let mut state = [Wrapping(0u64); 8];
                for (i, chunk) in bytes.chunks_exact(8).enumerate() {
                    if i >= 8 {
                        return Err(());
                    }
                    let word = u64::from_le_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6],
                        chunk[7],
                    ]);
                    state[i] = Wrapping(word);
                }
                Ok(Self::As64(state))
            }
            _ => Err(()),
        }
    }
}

pub(super) fn sha1_block_data_order<'d>(
    state: &mut DynState,
    data: &'d [u8],
    _cpu_features: cpu::Features,
) -> (usize, &'d [u8]) {
    let state = match state {
        DynState::As32(state) => state,
        _ => {
            unreachable!();
        }
    };

    let (full_blocks, leftover) = slice::as_chunks(data);
    sha1::sha1_block_data_order(state, full_blocks);
    (full_blocks.as_flattened().len(), leftover)
}

pub(super) fn sha256_block_data_order<'d>(
    state: &mut DynState,
    data: &'d [u8],
    cpu_features: cpu::Features,
) -> (usize, &'d [u8]) {
    let state = match state {
        DynState::As32(state) => state,
        _ => {
            unreachable!();
        }
    };

    let (full_blocks, leftover) = slice::as_chunks(data);
    sha2::block_data_order_32(state, full_blocks, cpu_features);
    (full_blocks.len() * sha2::SHA256_BLOCK_LEN.into(), leftover)
}

pub(super) fn sha512_block_data_order<'d>(
    state: &mut DynState,
    data: &'d [u8],
    cpu_features: cpu::Features,
) -> (usize, &'d [u8]) {
    let state = match state {
        DynState::As64(state) => state,
        _ => {
            unreachable!();
        }
    };

    let (full_blocks, leftover) = slice::as_chunks(data);
    sha2::block_data_order_64(state, full_blocks, cpu_features);
    (full_blocks.len() * sha2::SHA512_BLOCK_LEN.into(), leftover)
}
