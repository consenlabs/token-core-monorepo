# token-core-monorepo

合并token-core和imkey-core两个项目到一个workspace，使用统一的rust版本和依赖库版本进行编译，解决不同rust版本编译出来的库文件集成到
client端冲突问题，并提供Android包的publish到nexus功能

警告：还未应用到生产环境

## package
* `token-core` [token-core README](./token-core/README.md)
* `imkey-core` [imkey-core README](./imkey-core/README.md)
* `publish`  [publish README](./publish/README.md)
* `script`  Linux交叉编译脚本，主要用于CI发布Android库时调用


## Code Build
cargo build


## License
Apache Licence v2.0
