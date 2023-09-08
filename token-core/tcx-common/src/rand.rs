use rand::Rng;

#[inline]
pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut bytes = [0u8; N];
    rand::thread_rng().fill(&mut bytes[..]);
    bytes
}

#[inline]
pub fn random_u8_16() -> [u8; 16] {
    random_bytes::<16>()
}

#[inline]
pub fn random_u8_32() -> [u8; 32] {
    random_bytes::<32>()
}

#[inline]
pub fn random_u8_64() -> [u8; 64] {
    random_bytes::<64>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_u8_16() {
        let r1 = random_u8_16();
        let r2 = random_u8_16();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u8_32() {
        let r1 = random_u8_32();
        let r2 = random_u8_32();
        assert_ne!(r1, r2);
    }

    #[test]
    fn test_random_u8_64() {
        let r1 = random_u8_64();
        let r2 = random_u8_64();
        assert_ne!(r1, r2);
    }
}
