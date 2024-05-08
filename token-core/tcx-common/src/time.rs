use std::time::{SystemTime, UNIX_EPOCH};

#[inline]
pub fn unix_timestamp() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    since_the_epoch.as_secs() * 1000
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_unix_timestamp() {
        let timestamp = super::unix_timestamp();
        assert!(timestamp > 0);
    }
}
