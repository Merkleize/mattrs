use bitcoin::ScriptBuf;
use bitcoin::opcodes::all::*;

use crate::sha256;

/// Combine two 32-byte hashes: sha256(left || right).
pub fn combine_hashes(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut data = [0u8; 64];
    data[..32].copy_from_slice(left);
    data[32..].copy_from_slice(right);
    sha256(&data)
}

/// Check if n is a power of 2.
pub fn is_power_of_2(n: usize) -> bool {
    n >= 1 && (n & (n - 1)) == 0
}

/// Largest power of 2 strictly less than n (n must be > 1).
fn largest_power_of_2_less_than(n: usize) -> usize {
    assert!(n > 1);
    if is_power_of_2(n) {
        n / 2
    } else {
        1 << floor_lg(n)
    }
}

fn floor_lg(n: usize) -> u32 {
    assert!(n > 0);
    let mut r = 0;
    let mut t = 1;
    while 2 * t <= n {
        t *= 2;
        r += 1;
    }
    r
}

/// Compute the merkle root of a list of 32-byte leaves using a left-complete binary tree.
///
/// Matches pymatt's `MerkleTree([...]).root` / `make_tree` which splits
/// n leaves into left = largest_power_of_2_less_than(n) and right = remainder.
pub fn merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty(), "merkle_root requires at least 1 leaf");
    merkle_root_slice(leaves)
}

fn merkle_root_slice(leaves: &[[u8; 32]]) -> [u8; 32] {
    match leaves.len() {
        0 => panic!("empty"),
        1 => leaves[0],
        _ => {
            let split = largest_power_of_2_less_than(leaves.len());
            let left = merkle_root_slice(&leaves[..split]);
            let right = merkle_root_slice(&leaves[split..]);
            combine_hashes(&left, &right)
        }
    }
}

// ---------------------------------------------------------------------------
// Script helpers for on-chain merkle root computation
// ---------------------------------------------------------------------------

/// Reduces n stack elements to a single merkle root via repeated CAT SHA256.
///
/// Stack: x_0 x_1 ... x_{n-1} → ... root
///
/// This does NOT preserve the original elements (they are consumed).
/// The calling code should dup them first if needed.
pub fn merkle_root_script(n: usize) -> ScriptBuf {
    assert!(n >= 1);
    let mut bytes = Vec::new();
    let mut sz = n;
    while sz > 1 {
        let layer = reduce_merkle_layer_script(sz);
        bytes.extend_from_slice(layer.as_bytes());
        sz = (sz + 1) / 2;
    }
    ScriptBuf::from(bytes)
}

/// Reduces one layer: pairs adjacent elements with CAT SHA256.
/// If n is odd, the last element is kept (moved to altstack then back).
///
/// n=1: no-op
/// n=2: CAT SHA256
/// n odd: TOALTSTACK <reduce(n-1)> FROMALTSTACK
/// n even: CAT SHA256 TOALTSTACK <reduce(n-2)> FROMALTSTACK
fn reduce_merkle_layer_script(n: usize) -> ScriptBuf {
    assert!(n >= 1);
    let mut bytes = Vec::new();
    reduce_merkle_layer_inner(n, &mut bytes);
    ScriptBuf::from(bytes)
}

fn reduce_merkle_layer_inner(n: usize, out: &mut Vec<u8>) {
    if n <= 1 {
        return;
    }
    if n == 2 {
        out.push(OP_CAT.to_u8());
        out.push(OP_SHA256.to_u8());
        return;
    }
    if n % 2 == 1 {
        // odd: save last, reduce n-1, restore
        out.push(OP_TOALTSTACK.to_u8());
        reduce_merkle_layer_inner(n - 1, out);
        out.push(OP_FROMALTSTACK.to_u8());
    } else {
        // even: reduce last pair first, save result, reduce rest, restore
        out.push(OP_CAT.to_u8());
        out.push(OP_SHA256.to_u8());
        out.push(OP_TOALTSTACK.to_u8());
        reduce_merkle_layer_inner(n - 2, out);
        out.push(OP_FROMALTSTACK.to_u8());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    #[test]
    fn test_merkle_root_single() {
        let leaf = sha256(b"hello");
        assert_eq!(merkle_root(&[leaf]), leaf);
    }

    #[test]
    fn test_merkle_root_two() {
        let a = sha256(b"a");
        let b = sha256(b"b");
        let expected = combine_hashes(&a, &b);
        assert_eq!(merkle_root(&[a, b]), expected);
    }

    #[test]
    fn test_merkle_root_three() {
        // 3 leaves: left child gets 2 (largest power of 2 < 3), right child gets 1
        let a = sha256(b"a");
        let b = sha256(b"b");
        let c = sha256(b"c");
        let left = combine_hashes(&a, &b);
        let expected = combine_hashes(&left, &c);
        assert_eq!(merkle_root(&[a, b, c]), expected);
    }

    #[test]
    fn test_merkle_root_five() {
        // 5 leaves: left child gets 4, right child gets 1
        let leaves: Vec<[u8; 32]> = (0..5).map(|i| sha256(&[i])).collect();
        let l01 = combine_hashes(&leaves[0], &leaves[1]);
        let l23 = combine_hashes(&leaves[2], &leaves[3]);
        let left = combine_hashes(&l01, &l23);
        let expected = combine_hashes(&left, &leaves[4]);
        assert_eq!(merkle_root(&leaves), expected);
    }

    #[test]
    fn test_merkle_root_eight() {
        let leaves: Vec<[u8; 32]> = (0..8).map(|i| sha256(&[i])).collect();
        let l01 = combine_hashes(&leaves[0], &leaves[1]);
        let l23 = combine_hashes(&leaves[2], &leaves[3]);
        let l45 = combine_hashes(&leaves[4], &leaves[5]);
        let l67 = combine_hashes(&leaves[6], &leaves[7]);
        let l0123 = combine_hashes(&l01, &l23);
        let l4567 = combine_hashes(&l45, &l67);
        let expected = combine_hashes(&l0123, &l4567);
        assert_eq!(merkle_root(&leaves), expected);
    }

    #[test]
    fn test_is_power_of_2() {
        assert!(is_power_of_2(1));
        assert!(is_power_of_2(2));
        assert!(is_power_of_2(4));
        assert!(is_power_of_2(8));
        assert!(!is_power_of_2(3));
        assert!(!is_power_of_2(5));
        assert!(!is_power_of_2(6));
    }
}
