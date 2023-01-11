# Build imKey Core X

## Install Rust 
1. 安装 rustup    
`curl https://sh.rustup.rs -sSf | sh`    
安装完成后使用 `rustc --version` 确认是否安装成功，rustup 在安装过程中会附带安装 Rust 常用的 cargo 工具。    

2. 安装 Android 相关 target    
`rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android`    

3. 安装 iOS 相关 target    
`rustup target add aarch64-apple-ios armv7-apple-ios armv7s-apple-ios i386-apple-ios x86_64-apple-ios`    


## 配置 iOS 编译工具    
1. 安装 Xcode     
2. 安装 lipo 编译工具    
```    
cargo install cargo-lipo   
cargo install cbindgen   
```   
3. 运行 `token-core` 项目中的`tools/build-ios.sh`。注意`tools/build-ios.sh`的目录配置。该脚本将会编译相关的 .a 文件并拷贝到指定的目录中

## 配置 Android 编译工具  
1. 安装 Android SDK， Android Studio 会默认附带 Android SDK。也可以单独安装。Android Studio 附带的 SDK 目录在`/Users/xxx/Library/Android/sdk`   
2. 配置`~/.cargo/config`   
3. 运行 `imkey-core` 项目中的`tools/build-android-linux.sh`。注意目前android编译仅支持在linux系统上实现。

