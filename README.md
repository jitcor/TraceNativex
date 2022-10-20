# TraceNativex
支持c++ 函数名按原始函数名过滤，以及其他一些小功能
# 配置文件说明
```json
{
  "ignore_case":false,
  "cpp_demangle":false,
  "print_log":false,
  "reserve_symbol":false,
  "method_match_enable":false,
  "method_match":[
      "sub_*",
      "Java_*",
      "*_nativeEncrypt",
      "openssl::aes::*",
      "*model*"
  ]
}
```
- ignore_case 忽略大小写
- cpp_demangle 支持C++原始函数名过滤
- print_log 打印日志
- reserve_symbol 非匿名函数，保留原始符号
- method_match_enable 是否启用函数过滤
- method_match 函数名匹配规则
> 其中 openssl::aes::* 规则需要先开启 cpp_demangle ,才能生效  
