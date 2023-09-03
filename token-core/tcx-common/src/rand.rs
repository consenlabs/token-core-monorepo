use rand::Rng;

pub fn random_u8_16() -> [u8; 16] {
    rand::thread_rng().gen::<[u8; 16]>()
}

pub fn random_u8_32() -> [u8; 32] {
    rand::thread_rng().gen::<[u8; 32]>()
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
}
