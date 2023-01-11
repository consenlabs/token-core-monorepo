pushd ../proto/src
#rm -rf ../../ios/imKeyConnector/Classes/Proto
#mkdir ../../ios/imKeyConnector/Classes/Proto
#
#protoc --swift_opt=Visibility=Public --swift_out=../../ios/imKeyConnector/Classes/Proto api.proto
#protoc --swift_opt=Visibility=Public --swift_out=../../ios/imKeyConnector/Classes/Proto device.proto
#protoc --swift_opt=Visibility=Public --swift_out=../../ios/imKeyConnector/Classes/Proto btc.proto
#protoc --swift_opt=Visibility=Public --swift_out=../../ios/imKeyConnector/Classes/Proto eth.proto
#protoc --swift_opt=Visibility=Public --swift_out=../../ios/imKeyConnector/Classes/Proto eos.proto
#protoc --swift_opt=Visibility=Public --swift_out=../../ios/imKeyConnector/Classes/Proto cosmos.proto

rm -rf ../../wrapper/ios/imKeyConnector/Proto
mkdir ../../wrapper/ios/imKeyConnector/Proto

protoc --swift_opt=Visibility=Public --swift_out=../../wrapper/ios/imKeyConnector/Proto api.proto
protoc --swift_opt=Visibility=Public --swift_out=../../wrapper/ios/imKeyConnector/Proto device.proto
protoc --swift_opt=Visibility=Public --swift_out=../../wrapper/ios/imKeyConnector/Proto btc.proto
protoc --swift_opt=Visibility=Public --swift_out=../../wrapper/ios/imKeyConnector/Proto eth.proto
protoc --swift_opt=Visibility=Public --swift_out=../../wrapper/ios/imKeyConnector/Proto eos.proto
protoc --swift_opt=Visibility=Public --swift_out=../../wrapper/ios/imKeyConnector/Proto cosmos.proto
popd