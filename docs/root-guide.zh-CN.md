# NeXXt One（FGA221D / GDNT-S）Root 与诊断完整指南（中文）

> **适用对象**：想完全掌控自己网关的 Fastweb NeXXt One 用户。
> 全部内容在固件 `22.2.0378_FW_058_FGA221D`（前端资源时间戳 `20260515082010`）上实测。
> 本仓库所有工具均为原创，未使用任何社区利用代码。

**目录**：0 安全模型 · 1 设备事实 · 2 Web 会话与登录 · 3 命令注入 · 4 时序神谕 ·
5 可靠文件传输 · 6 持久 SSH · 7 防火墙真相与精确放行 · 8 排障速查 · 9 FAQ · 10 恢复与安全 ·
11 声明式配置 · 12 WireGuard 远程访问 · 13 兼容性数据与报告 · 14 无硬件开发

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
- **脚本登录失败的根因（已解决）**：确认步骤只会认证**最新创建**的会话
  （`sessionmgr.lua:newSession` 每建一个会话就写入 `uci.fastweb.sessions.@sessions.sessionid`，
  `login.wat` 拿它和调用者比对）。如果有别人（比如浏览器标签页）在你之后建过会话，
  确认就会静默失败。解法：清空本地 Cookie → 请求一次 `/login` 铸造全新会话 →
  期间不要在浏览器打开路由器页面。`nexxt session login` 已自动完成这些。
- **兜底**：浏览器登录一次，然后 `nexxt session import-cookie <sessionID|capture.har>`。
  浏览器不退出登录，会话一直有效。
- **TLS 指纹固定（v1.6.0+）**：设备证书是自签的，因此不做 CA 验证。先运行一次
  `nexxt session fingerprint`，之后加 `--tls-fingerprint <sha256>` 固定证书，
  可发现 LAN 上被替换的 TLS 端点。

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

## 5. 可靠文件传输（统一 CLI：`nexxt transfer`）

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
7. v1.6.0 起，`--tag` 和目标路径在发送任何分段前就会经过严格白名单校验——
   目标必须是不含 shell 元字符的绝对路径。

## 6. 持久 SSH（统一 CLI：`nexxt ssh`）

`bootstrap` 做的事（全部可逆）：

1. 把 root 原始账户行以 0600 权限保存到 `/etc/nexxt-toolkit/`，再把 shell 从
   `/bin/restricted_shell` 改为 `/bin/ash`；回滚记录重启后仍在。
2. 端到端校验 **RSA** 公钥，记录本工具拥有的精确一行，再追加到两个授权文件；
   不覆盖任何既有密钥。
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

`teardown` 删除实例、只移除本工具记录的密钥，并恢复安装前保存的完整 root 账户行。
v1.4.0 或更早安装没有持久所有权记录，需要用 `ssh bootstrap ... --adopt-legacy`
明确迁移一次；没有这个许可时，工具拒绝猜测和破坏性清理。

**主机密钥验证（v1.6.0+）**：`nexxt ssh run`、`nexxt fw` 等所有走 SSH 的命令现在默认
TOFU（首次信任）dropbear 主机密钥，记录在 `~/.nexxt-one-toolkit/known_hosts`
（0700/0600）。密钥变化会直接拒绝连接而不是静默放行；设备确实重装过时，可用
`ssh run --no-verify-host-key` 显式退回旧行为。

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

日常优先使用 `nexxt fw ensure`：同名规则会幂等更新，修改前备份 firewall UCI，
重载失败会自动恢复。`nexxt fw audit` 检查重名、过宽 WAN 放行和未落到运行表的规则。

真实入站测试使用 `nexxt inbound observe --rule 名称 --key 私钥`，在窗口内从外网
**新建**连接。计数增加可证明包已到网关；零增量只表示“未观察到”，不能证明阻断，
因为客户端没发包、硬件快转和上游过滤都可能导致零计数。WAN 是私网地址本身也不能证明
CGNAT 阻断，运营商仍可能提供上游 1:1 NAT。

## 8. 排障速查

| 现象 | 原因 / 处理 |
|---|---|
| 按键后 `login_status` 仍为 0 | 会话绑定浏览器上下文；改用 HAR cookie 导入 |
| 注入命令"没执行" | `>` 被剥（用 tee）/ 内容过滤（二分）/ 沙盒网络命名空间（网络操作注定失败） |
| 长请求被静默忽略 | host 长度/内容限制——拆短 |
| dropbear 起来了但密钥被拒 | ed25519 不支持（用 RSA）；文件须以换行结尾；`/bin/restricted_shell` 会挡登录 |
| 入站观察为 `not-observed` | 结论未知；从外网新建流量，并检查硬件快转和上游状态 |
| 旧 SSH 修改没有所有权记录 | 只有确认由 v1.4.0 或更早工具创建时才用 `--adopt-legacy` |
| 传输后文件内容不对 | 迟到/乱序执行覆盖了正确内容——重新审计分段并重写坏段 |

## 9. FAQ

- **需要物理接触吗？** 需要——会话来自机身按键（或复用按键建立的会话）。
- **会变砖吗？** 本指南不涉及 flash 布局、固件镜像、启动 bank、TR-069。teardown 可还原。
- **固件升级后还有效吗？** 当作无效处理，运行 `nexxt audit-update --key 私钥`，
  它会记录固件指纹并检查 SSH 策略、持久回滚状态和防火墙运行态。
- **运营商的 dropbear.wan？** 别碰，它限制在运营商网段且有 2FA。

## 10. 恢复与安全

- 首选恢复方式：`./nexxt ssh teardown`，它依据持久所有权记录精确还原，并保留无关密钥。
- `--legacy-force` 只适用于已确认的 v1.4.0 或更早安装；它会使用旧版整文件清理行为。
- `/tmp` 产物重启自清；立即清理：`rm -f /tmp/nx* /tmp/k*.b64`。
- 浏览器 HAR 含 `sessionID`，还可能含 VoIP 凭据（`deviceinfo` 会泄露 base64 的 SIP 密码）——用完删除。
- 提公开 issue 前运行 `nexxt support-bundle`；它只允许安全固件字段，并自动删除 Cookie、
  凭据、MAC、序列号和原始 IP。上传前仍要人工查看 `report.json`。

## 11. 声明式配置（`nexxt apply` / `nexxt diff`）

除了一条条执行 `fw ensure`，还可以用一个 JSON 文件描述期望状态（见 `examples/nexxt.json`）：

```json
{
  "version": 1,
  "firewall": {
    "rules": [
      {"name": "Allow-AWG-v6", "proto": "udp",
       "dest_ip": "2001:db8::123", "dest_port": 51820}
    ]
  },
  "ssh": {"require_key_only": true, "require_lan_only": true}
}
```

- `nexxt diff -f config.json --key K` 是只读的：打印计划（CREATE/UPDATE/DELETE/NOOP
  及 SSH 策略检查），有待变更时退出码为 2。
- `nexxt apply -f config.json --key K` 执行收敛：防火墙规则走与 CLI 相同的幂等、
  备份-回滚 `ensure` 路径；SSH 策略断言（`require_key_only`/`require_lan_only`）
  不满足时在任何修改之前中止。
- 重复 apply 是空操作。可选 `"prune": true` 只删除“toolkit 形状”的多余规则
  （有名字、`src=wan`、ACCEPT、带 dest_ip+dest_port），其余一概不碰。

## 12. WireGuard 远程访问（`nexxt vpn wireguard`）

开放针孔最常见的理由就是从外网经 WireGuard 回家。一条命令搞定密钥、配置和网关规则：

```bash
nexxt vpn wireguard --key ~/.ssh/nexxt_rsa \
  --server-ipv6 2001:db8::123 --client phone --client laptop
```

- 密钥在本地用纯 Python 生成（RFC 7748 X25519，通过官方测试向量验证）——两端都不需要
  安装 `wg` 工具。
- 每个客户端独立密钥对 + 独立 PSK；配置写入 `~/.nexxt-one-toolkit/wireguard/`
  （目录 0700、文件 0600），私钥绝不出现在 stdout 或 `--json` 输出里。
- WireGuard 服务端运行在 LAN 内一台常开设备上（NAS、树莓派……）——按安全模型，
  网关上不安装任何第三方软件，网关侧只通过 `fw ensure` 加一条幂等 IPv6 UDP 针孔。
- `--no-pinhole` 只生成配置不动网关；`--force` 覆盖已有配置文件。之后客户端发起握手时跑
  `nexxt inbound observe --rule Allow-WG-v6` 即可端到端验证通路。

## 13. 兼容性数据与报告

固件指纹是数据而不是代码：`nexxt_toolkit/compat.json` 列出已知的板型/型号/固件组合，
随包发布。注入守卫对未知板型直接拒绝，对板型匹配但固件未收录的设备给出警告
（`untested`），`--force` 可覆盖两者。公开矩阵维护在 `COMPATIBILITY.md`。
如果你的固件不在列表里，运行 `nexxt probe --report`，把生成的 Markdown 直接粘贴到
compatibility issue 即可——内容只有探测数据，无需脱敏。

## 14. 无硬件开发（`nexxt simulate`）

`nexxt simulate` 在 `127.0.0.1` 上启动一个假网关：实现了探测指纹用的静态前端资源、
按键登录握手（虚拟 `press_buttons`）、会话 TTL，以及由内存文件系统和 shell 子集解释器
支撑的注入通道（`tee`、`grep`、`base64`、`md5sum`、可调时间缩放的 `sleep` 等）。

```bash
nexxt simulate --time-scale 0.1
nexxt --base-url http://127.0.0.1:<端口> probe
nexxt --base-url http://127.0.0.1:<端口> session login
```

集成测试（`tests/test_simulator.py`）就是对它跑 probe、登录、时序神谕、`verify` 和
一次完整 md5 校验的 `transfer`。扩展工具箱时先在模拟器上跑通全流程，最后再用真机验证。
