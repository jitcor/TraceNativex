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
- chatGPT给的方案
```python
import re

text = open(r"F:\task\wechat\7.0.20\data\lib\arm64-v8a\libwechatmm_1711448001.txt.log","rb").read().decode()

# 使用正则表达式匹配以"sub_"开头的子函数标识符
sub_functions = re.findall(r'sub_[a-fA-F0-9]+', text)

# 创建一个空字典来存储每个子函数及其出现次数
sub_function_counts = {}

# 遍历子函数列表，统计每个子函数的出现次数
for sub_function in sub_functions:
    if sub_function in sub_function_counts:
        sub_function_counts[sub_function] += 1
    else:
        sub_function_counts[sub_function] = 1

# 按出现次数从大到小对子函数进行排序
sorted_sub_functions = sorted(sub_function_counts.items(), key=lambda x: x[1], reverse=True)

# 打印排序后的结果
for sub_function, count in sorted_sub_functions:
    print(f"{sub_function}: {count}")

```
### 效果图
![image](https://user-images.githubusercontent.com/27600008/197162604-301ca235-e815-4464-9a5b-536408e468cf.png)


# 加入星球不迷路
[Humenger](https://github.com/Humenger)
