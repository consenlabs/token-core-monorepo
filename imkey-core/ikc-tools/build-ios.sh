pushd ../api
if ! type "cargo-lipo" > /dev/null; then
    cargo install cargo-lipo
    rustup target add aarch64-apple-ios x86_64-apple-ios armv7-apple-ios armv7s-apple-ios i386-apple-ios
fi

# cargo lipo --release --targets aarch64-apple-ios,armv7-apple-ios,armv7s-apple-ios,x86_64-apple-ios,i386-apple-ios
cargo lipo --release --targets aarch64-apple-ios # for debug
cbindgen src/lib.rs -l c > ../target/connector.h

#cp ../target/universal/release/libconnector.a ../ios/imKeyConnector/Classes/include/libconnector.a
#cp ../target/connector.h ../ios/imKeyConnector/Classes/include/connector.h


cp ../target/universal/release/libconnector.a ../wrapper/ios/imKeyConnector/Classes/include/libconnector.a
cp ../target/connector.h ../wrapper/ios/imKeyConnector/Classes/include/connector.h
popd