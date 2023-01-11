#
# Be sure to run `pod lib lint imKeyConnector.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'imKeyConnector'
  s.version          = '0.1.0'
  s.summary          = 'A short description of imKeyConnector.'

# This description is used to generate tags and improve search results.
#   * Think: What does it do? Why did you write it? What is the focus?
#   * Try to keep it short, snappy and to the point.
#   * Write the description between the DESC delimiters below.
#   * Finally, don't worry about the indent, CocoaPods strips it!

  s.description      = <<-DESC
TODO: Add long description of the pod here.
                       DESC

  s.homepage         = 'https://github.com/Neal Xu/imKeyConnector'
  # s.screenshots     = 'www.example.com/screenshots_1', 'www.example.com/screenshots_2'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Neal Xu' => 'imxuneal@gmail.com' }
  s.source           = { :git => 'https://github.com/Neal Xu/imKeyConnector.git', :tag => s.version.to_s }
  # s.social_media_url = 'https://twitter.com/<TWITTER_USERNAME>'

  s.ios.deployment_target = "9.0"
  
  s.source_files = "imKeyConnector/Classes/**/*.{h,m,swift,a}"
  s.swift_version = "4"
  s.ios.vendored_library = "imKeyConnector/Classes/include/libFtBTKeyApi.a"
  s.pod_target_xcconfig = {
    "OTHER_LDFLAGS" => "-lObjC",
    "SWIFT_OPTIMIZATION_LEVEL" => "-Owholemodule"
  }
  
  
  

  # s.resource_bundles = {
  #   'imKeyConnector' => ['imKeyConnector/Assets/*.png']
  # }

  # s.public_header_files = 'Pod/Classes/**/*.h'

#  s.default_subspec = 'CoreBitcoin'


  s.dependency "CryptoSwift", "~> 1.3"
#  s.dependency "BigInt", "3.0.0"
  s.dependency "GRKOpenSSLFramework"
#  s.dependency "CoreBitcoin"
#  s.dependency "secp256k1.swift"
#  s.dependency "OrderedDictionary", "~> 1.4"
  s.dependency "SwiftProtobuf", "~> 1.0"
  s.dependency "imKeyBleLib"
end
