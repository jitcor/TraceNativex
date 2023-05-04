# -*- coding:utf-8 -*-
import json

from ida_idaapi import PLUGIN_SKIP
from idaapi import plugin_t
from idaapi import PLUGIN_PROC
from idaapi import PLUGIN_OK
import ida_nalt
import idaapi
import idautils
import idc
import time

import os
import re
import ida_kernwin
import pydevd_pycharm
#pydevd_pycharm.settrace('localhost', port=5070, stdoutToServer=True, stderrToServer=True)


def_config_json = """
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
"""
config_file_path = os.path.dirname(__file__) + "/TraceNativex_v5.config"


class EditConfigFileAlert(ida_kernwin.Form):
    def __init__(self):
        F = ida_kernwin.Form
        self.config_json = def_config_json
        if os.path.exists(config_file_path):
            try:
                self.config_json = open(config_file_path, "rb").read().decode()
            except Exception as e:
                print("Read config error: ", e)
                return
        F.__init__(self, r"""STARTITEM 0
BUTTON YES* apply
BUTTON NO reset
BUTTON CANCEL cancel
Edit configuration file

<:{txtMultiLineText}>
""", {
            'txtMultiLineText': F.MultiLineTextControl(text=self.config_json),
        })

    @staticmethod
    def show(execute=True) -> (int, str):
        f = EditConfigFileAlert()
        f, args = f.Compile()
        if execute:
            result = f.Execute()
            text = f.txtMultiLineText.text
            f.Free()
            return result, text
        f.Free()


def execCmd(cmd):
    r = os.popen(cmd)
    text = r.read()
    r.close()
    return text


def fix(name):
    if len(name) > 0 and name.find("sub_") < 0:
        return execCmd('{}/demumble.exe {}'.format(os.path.dirname(__file__), name))


# 获取SO文件名和路径
def getSoPathAndName():
    fullpath = ida_nalt.get_input_file_path()
    filepath, filename = os.path.split(fullpath)
    return filepath, filename


# 获取代码段的范围
def getSegAddr():
    textStart = []
    textEnd = []
    for seg in idautils.Segments():
        if (idc.get_segm_name(seg)).lower() == '.text' or (
                idc.get_segm_name(seg)).lower() == 'text' or(
                idc.get_segm_name(seg)).lower()=='__text':
            tempStart = idc.get_segm_start(seg)
            tempEnd = idc.get_segm_end(seg)
            textStart.append(tempStart)
            textEnd.append(tempEnd)

    return min(textStart), max(textEnd)


def check_method_match(method_match: str, functionName: str, ignore_case=False):
    if method_match and functionName:
        result = False
        if ignore_case:
            if method_match.startswith("*") and method_match.endswith("*"):
                result = functionName.upper().find(method_match[1:-1].upper()) >= 0
            if method_match.startswith("*"):
                result = functionName.upper().endswith(method_match[1:].upper())
            if method_match.endswith("*"):
                result = functionName.upper().startswith(method_match[:-1].upper())
            return result or functionName.upper().find(method_match.upper()) >= 0
        if method_match.startswith("*") and method_match.endswith("*"):
            result = functionName.find(method_match[1:-1]) >= 0
        if method_match.startswith("*"):
            result = functionName.endswith(method_match[1:])
        if method_match.endswith("*"):
            result = functionName.startswith(method_match[:-1])
        return result or functionName.find(method_match) >= 0


class TraceNativex(plugin_t):
    flags = PLUGIN_PROC
    comment = "TraceNativex"
    help = ""
    wanted_name = "TraceNativex"
    wanted_hotkey = ""

    def init(self):
        if idaapi.IDA_SDK_VERSION < 700:
            print("TraceNativex(v1.0) plugin only support 7.0 or later")
            return PLUGIN_SKIP
        print("TraceNativex(v1.0) plugin has been loaded.")
        return PLUGIN_OK

    def run(self, arg):
        code, result = EditConfigFileAlert.show()
        if code == -1:
            print("Cancel build trace by user")
            return
        print(result)
        try:
            config = json.loads(result)
        except Exception as e:
            print("Parse config error: ", e)
            return
        try:
            open(config_file_path, "wb").write(result.encode())
        except Exception as e:
            print("Save config error: ", e)
            return
        method_match_enable = config['method_match_enable']
        ignore_case = config['ignore_case']
        method_match = config['method_match']
        cpp_demangle = config['cpp_demangle']
        print_log = config['print_log']
        reserve_symbol = config['reserve_symbol']
        print(method_match_enable)
        print(ignore_case)
        if cpp_demangle:
            print("Note: Turning on cpp_demangle will be very time consuming")

        # 查找需要的函数
        ea, ed = getSegAddr()
        search_result = []
        search_func_result = []
        for func in idautils.Functions(ea, ed):
            try:
                functionName = str(idaapi.ida_funcs.get_func_name(func))
                if cpp_demangle:
                    functionNameFix = fix(functionName)
                if method_match_enable:
                    is_match = False
                    for match in method_match:
                        if check_method_match(match, functionName, ignore_case):
                            is_match = True
                            break
                        elif cpp_demangle:
                            if check_method_match(match, functionNameFix, ignore_case):
                                is_match = True
                                break
                    if is_match:
                        if print_log:
                            print("Trace func:", functionName)
                        if reserve_symbol and not functionName.startswith("sub_"):
                                search_func_result.append(functionName)
                        elif len(list(idautils.FuncItems(func))) > 10:# 函数指令条数大于10
                            # 如果是thumb模式，地址+1
                            arm_or_thumb = idc.get_sreg(func, "T")
                            if arm_or_thumb:
                                func += 1
                            search_result.append(hex(func))
            except Exception as e:
                print(e)

        so_path, so_name = getSoPathAndName()
        script_name = so_name.split(".")[0] + "_" + str(int(time.time())) + ".txt"
        save_path = os.path.join(so_path, script_name)
        if reserve_symbol:
            search_func_result = [f"-i '{so_name}!{func}'" for func in search_func_result]
        search_func_result = " ".join(search_func_result)

        search_result = [f"-a '{so_name}!{offset}'" for offset in search_result]
        search_result = " ".join(search_result)

        with open(save_path, "w", encoding="utf-8") as F:
            F.write(search_func_result+" "+search_result)

        print("使用方法如下：")
        print(f"frida-trace -UF -O {save_path}")

    def term(self):
        pass


def PLUGIN_ENTRY():
    return TraceNativex()

# PLUGIN_ENTRY().run(None)
