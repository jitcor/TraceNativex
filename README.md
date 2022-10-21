# TraceNativex
支持c++ 函数名按原始函数名过滤，以及其他一些小功能
# 安装
跟traceNatives一样放入IDA 插件目录即可，只不过多了一个demumble.exe文件    
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
# TraceNativex辅助分析小工具
### 实现了统计函数调用次数工具  
```python

import re

if __name__ == '__main__':
   trace= open("libgaea_1666336601.trace","rb").read().decode()
   counts={}
   for item in re.compile("[a-zA-Z0-9_]*?\\(\\)").findall(trace):
      if counts.get(item):
         counts[item]=counts[item]+1
      else:
         counts[item]=1
   for key in counts:
      print(key,"->",counts[key])

```
### 效果图
![image](https://user-images.githubusercontent.com/27600008/197162604-301ca235-e815-4464-9a5b-536408e468cf.png)


# 加入星球不迷路
[Humenger](https://github.com/Humenger)
