use array::{Span, ArrayTrait, SpanTrait, ArrayDrop};
use integer::TryInto;
use option::OptionTrait;
use starknet::SyscallResultTrait;

const KECCAK_FULL_RATE_IN_BYTES: usize = 136;


fn u128_to_u64(input: u128) -> u64 {
    input.try_into().unwrap()
}

fn u128_split(input: u128) -> (u64, u64) {
    let (high, low) = integer::u128_safe_divmod(
        input, 0x10000000000000000_u128.try_into().unwrap()
    );

    (u128_to_u64(high), u128_to_u64(low))
}

fn keccak_add_u256_le(ref keccak_input: Array::<u64>, v: u256) {
    let (high, low) = u128_split(v.low);
    keccak_input.append(low);
    keccak_input.append(high);
    let (high, low) = u128_split(v.high);
    keccak_input.append(low);
    keccak_input.append(high);
}


// Computes the keccak256 of multiple u256 values.
// The input values are interpreted as little-endian.
// The 32-byte result is represented as a little-endian u256.
fn keccak_u256s_le_inputs(mut input: Span<u256>) -> u256 {
    let mut keccak_input: Array::<u64> = Default::default();

    loop {
        match input.pop_front() {
            Option::Some(v) => {
                keccak_add_u256_le(ref keccak_input, *v);
            },
            Option::None(_) => {
                break ();
            },
        };
    };

    add_padding(ref keccak_input);
    starknet::syscalls::keccak_syscall(keccak_input.span()).unwrap_syscall()
}

fn keccak_add_u256_be(ref keccak_input: Array::<u64>, v: u256) {
    let (high, low) = u128_split(integer::u128_byte_reverse(v.high));
    keccak_input.append(low);
    keccak_input.append(high);
    let (high, low) = u128_split(integer::u128_byte_reverse(v.low));
    keccak_input.append(low);
    keccak_input.append(high);
}

// Computes the keccak256 of multiple u256 values.
// The input values are interpreted as big-endian.
// The 32-byte result is represented as a little-endian u256.
fn keccak_u256s_be_inputs(mut input: Span<u256>) -> u256 {
    let mut keccak_input: Array::<u64> = Default::default();

    loop {
        match input.pop_front() {
            Option::Some(v) => {
                keccak_add_u256_be(ref keccak_input, *v);
            },
            Option::None(_) => {
                break ();
            },
        };
    };

    add_padding(ref keccak_input);
    starknet::syscalls::keccak_syscall(keccak_input.span()).unwrap_syscall()
}


// The padding in keccak256 is "1 0* 1".
// `last_input_num_bytes` is the number of bytes in the last u64 input (0-7).
// TODO(yg): change u8 to u32?
fn add_padding(ref input: Array<u64>, last_input_u64: u64, last_input_num_bytes: u8) {
    // TODO(yg): verify 0 <= last_input_num_bytes <= 7?
    // TODO(yg): is one of the options cheaper?
    // Option1:
    let divisor17 = KECCAK_FULL_RATE_IN_U64.try_into().unwrap();
    let (q, r) = integer::u32_safe_divmod(input.len(), divisor17) * 8 + last_input_num_bytes.into();
    // Option2:
    // let divisor136 = KECCAK_FULL_RATE_IN_BYTES.try_into().unwrap();
    // let (q, r) = integer::u32_safe_divmod(input.len() * 8 + last_input_num_bytes.into(), divisor);
    let padding_len = KECCAK_FULL_RATE_IN_BYTES - r;
    // padding_len is in the range [1, KECCAK_FULL_RATE_IN_BYTES].

    // 0 <= padding_residue <= 7, 0 <= full_u64_padding <= 17.
    let (full_u64_padding, padding_residue) = integer::u32_safe_divmod(padding_len, 8);
    // TODO(yg): is "1 0* 1" in bits or bytes? That is - should there be at least 2 bytes of padding?
    if full_u64_padding == 0 {
        // TODO(yg): change to match.
        let last_u64 = if padding_residue == 1 {
            // TODO(yg): is the last input u64 glued to the right or left? This supposed it glued to the
            // right. If to the left, remove the shift. Same for the other cases.
            last_input_u64 << 8 + 0x81
        }
        else if padding_residue == 2 {
            last_input_u64 << 16 + 0x8001
        }
        else if padding_residue == 3 {
            last_input_u64 << 24 + 0x800001
        }
        else if padding_residue == 4 {
            last_input_u64 << 32 + 0x80000001
        }
        else if padding_residue == 5 {
            last_input_u64 << 40 + 0x8000000001
        }
        else if padding_residue == 6 {
            last_input_u64 << 48 + 0x800000000001
        }
        else if padding_residue == 7 {
            last_input_u64 << 56 + 0x80000000000001
        };
        input.append(last_u64);
        return;
    }

// TODO(ygg): continue. Go over all cases of padding...
    // full_u64_padding >= 1
    // TODO(yg): change to match.
    let first_padding_u64 = if padding_residue == 0 {
        1
    }
    else if padding_residue == 1 {
        // TODO(yg): is the last input u64 glued to the right or left? This supposed it glued to the
        // right. If to the left, remove the shift (and change to a single case...).
        last_input_u64 << 8 + 1
    }
    else if padding_residue == 2 {
        last_input_u64 << 16 + 1
    }
    else if padding_residue == 3 {
        last_input_u64 << 24 + 1
    }
    else if padding_residue == 4 {
        last_input_u64 << 32 + 1
    }
    else if padding_residue == 5 {
        last_input_u64 << 40 + 1
    }
    else if padding_residue == 6 {
        last_input_u64 << 48 + 1
    }
    else if padding_residue == 7 {
        last_input_u64 << 56 + 1
    };
    input.append(first_padding_u64);

    finalize_padding(ref input, full_u64_padding - 1);
}

// Finalize the padding by appending "0* 1".
// TODO(yg): change u32 to u8?
fn finalize_padding(ref input: Array<u64>, full_u64_padding: u32) {
    if (padding_len == 0) {
        return ();
    }

    input.append(0);
    input.append(0x8000000000000000);
    finalize_padding(ref input, padding_len - 1);
}
