pub fn version_at_least(version: &str, minimum: (u64, u64, u64)) -> bool {
    let parts = version
        .split('.')
        .take(3)
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>();

    let Ok(parts) = parts else {
        return false;
    };
    if parts.len() != 3 {
        return false;
    }

    (parts[0], parts[1], parts[2]) >= minimum
}

pub fn u64_to_be_bytes_vec(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

pub fn xpub_prefix_for_network_name(network: &str) -> [u8; 4] {
    if network == "MAINNET" {
        [0x04, 0x88, 0xb2, 0x1e]
    } else {
        [0x04, 0x35, 0x87, 0xcf]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compares_semver_like_versions_numerically() {
        assert!(!version_at_least("1.6.10", (1, 6, 11)));
        assert!(version_at_least("1.6.11", (1, 6, 11)));
        assert!(version_at_least("1.7.0", (1, 6, 11)));
        assert!(!version_at_least("1.6", (1, 6, 11)));
        assert!(!version_at_least("1.6.beta", (1, 6, 11)));
    }

    #[test]
    fn encodes_u64_as_fixed_width_big_endian() {
        assert_eq!(hex::encode(u64_to_be_bytes_vec(111111)), "000000000001b207");
        assert_eq!(
            hex::encode(u64_to_be_bytes_vec(1111111111111111111)),
            "0f6b75ab2bc471c7"
        );
    }
}
