pushd api
if ! type "cargo-lipo" > /dev/null; then
    cargo install cargo-lipo
    rustup target add aarch64-apple-ios x86_64-apple-ios armv7-apple-ios armv7s-apple-ios i386-apple-ios
fi

# cargo lipo --release --targets aarch64-apple-ios,armv7-apple-ios,armv7s-apple-ios,x86_64-apple-ios,i386-apple-ios
cargo lipo --release --targets aarch64-apple-ios # for debug
cbindgen src/lib.rs -l c > ../target/connector.h

#cp ../target/universal/release/libconnector.a ../ios/imKeyConnector/Classes/include/libconnector.a
#cp ../target/connector.h ../ios/imKeyConnector/Classes/include/connector.h


cp ../target/universal/release/libconnector.a ../examples/ios/iosExample/include/libconnector.a
cp ../target/connector.h ../examples/ios/iosExample/include/connector.h
popd

rm -rf examples/ios/iosExample/proto
mkdir examples/ios/iosExample/proto

pushd proto/src
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto api.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto device.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto btc.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto eth.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto eos.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto cosmos.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto tron.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto substrate.proto
protoc --swift_opt=Visibility=Public --swift_out=../../examples/ios/iosExample/proto common.proto
popd