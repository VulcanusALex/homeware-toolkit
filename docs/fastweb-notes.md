# Fastweb 网络侧调查结果（CGNAT 与 6rd 入站过滤）

> 这份笔记回答一个反复出现的问题："我的设备已经 root 了，为什么外网还是连不进来？"
> 结论先行：**这不是你设备的问题，Fastweb 对入站双栈全堵。** 调查过程与证据如下。

## 1. IPv4：名义公网，实际 CGNAT

- 客服确认账户"已开通静态公网 IPv4"，出站查询也确实显示一个公网地址。
- 但 CPE 的 WAN 接口上配置的是**私网地址**（示例：`10.64.23.145/22`，网关 `10.64.20.1`），
  强制 DHCP 重新协商后依然如故。
- 意大利社区有完全一致的案例：静态 IP"已开通"但 CPE 拿不到，最终要靠 Fastweb 后台
  **reprovisioning** 解决（客服原话 "CPE non NAT444 - Reprovisioning non previsto"）。
- 结论：公网地址只是上游 NAT 的出网映射，**入站包根本不会送达 CPE**。在 CPE 上做的任何
  端口映射都是对的、但等不到包。

## 2. IPv6：6rd 出站正常，入站不过 CPE

- Fastweb 住宅宽带的 IPv6 走 **6rd 隧道**（DHCPv4 option 212 下发参数），LAN 得到
  `2001:b07:xxxx:xxxx::/64` 前缀。前缀内嵌的就是 WAN 的 IPv4：
  示例前缀 `...:a40:1791::/64` → 字节 `10.64.23.145`（0a=10, 40=64, 17=23, 91=145），即当前私网 WAN 地址。
- 出站 IPv6 完全正常（CPE → 6rd BR anycast 81.208.50.214）。
- 入站实测：用外部 IPv6 TCP 扫描服务对 CPE 下游主机的全局地址发起连接，
  同时在 CPE 上 tcpdump：**v6 SYN 与 6rd 封装包（proto 41）均为零**，而扫描器收到
  "Connection refused"（Fastweb 网内设备代答的 ICMP 不可达）。
- 结论：**6rd 入站被 Fastweb 网络侧终结/无路由**。根因是 6rd 要求"真实可路由 IPv4"，
  CGNAT 下先天不成立。

## 3. 这意味着什么

| 层面 | 能做/不能做 |
|---|---|
| CPE/内网 | 配置已全部就绪（监听、防火墙精确放行），没有可改进项 |
| 运营商网内 | 入站双栈全堵，CPE 侧 root 也够不着 |
| 客户端侧 | 需要有 IPv6 才能走 v6 路线（手机 APN 开 IPv4/IPv6 双栈即可） |

**可行出路：**

1. **让 Fastweb 完成静态公网 IPv4 的 provisioning**（治本）。IPv4 真正下发到 WAN 后，
   6rd 前缀会随之内嵌新公网地址，IPv6 入站大概率同步恢复——CPE 侧零改动。
   给客服的话术见下。
2. **VPS 中继**（立即可用）：出站链路完全正常，让内网设备主动连一台有公网 IP 的 VPS
   建隧道，外部客户端连 VPS 中转。不受 Fastweb 任何限制。

## 4. 给 Fastweb 的话术（意大利语）

### 简短版（在线客服）

> Buongiorno, ho bisogno di aiuto con il mio **IP pubblico statico**, che secondo la vostra assistenza è già attivo sul mio account.
>
> Il problema: sulla WAN del mio NeXXt One c'è ancora un **indirizzo privato: 10.64.23.145/22** (gateway 10.64.20.1), anche dopo un rinnovo DHCP forzato. Di conseguenza **nessuna connessione in ingresso raggiunge il mio CPE**, né su IPv4 (ho configurato il port forwarding), né su IPv6 (il prefisso 6rd incorpora proprio l'IPv4 privato).
>
> Potete verificare e **completare il provisioning dell'IP pubblico statico sulla mia linea**, in modo che l'indirizzo pubblico venga assegnato direttamente alla WAN del NeXXt?

### 详细版（工单/邮件）

> **Oggetto: IP pubblico statico non assegnato alla WAN del CPE – richiesta verifica provisioning**
>
> Buongiorno,
>
> sono un cliente Fastweb con connessione FTTH e gateway **NeXXt One (FGA221D)**. L'assistenza mi ha confermato che sul mio account è attivo un **indirizzo IPv4 pubblico statico**, ma l'indirizzo non risulta assegnato alla mia linea. Di seguito i fatti tecnici verificati:
>
> 1. La WAN del NeXXt One ha l'indirizzo **10.64.23.145/22** (gateway 10.64.20.1), cioè un **indirizzo privato/CGNAT**, non quello pubblico. Un rinnovo DHCP forzato (riavvio dell'interfaccia WAN) non cambia l'assegnazione.
> 2. L'indirizzo pubblico visibile in uscita è **93.x.x.x**（你的公网 IPv4）, ma risulta solo un NAT in uscita: **nessuna connessione in ingresso raggiunge il CPE**.
> 3. Ho configurato correttamente il port forwarding (UDP 51820 verso un host interno) e verificato che il firewall del CPE non è la causa: **i pacchetti in ingresso non arrivano proprio al CPE** (verificato con contatori firewall e tcpdump sul gateway).
> 4. Anche IPv6 ha lo stesso problema: il prefisso 6rd assegnatomi (**2001:b07:a40:1791::/64**) incorpora proprio l'IPv4 privato 10.64.23.145, e i pacchetti IPv6 in ingresso (inclusi quelli incapsulati 6rd, protocollo 41) **non raggiungono mai il CPE**.
>
> **Cosa chiedo:**
>
> 1. Verificare che il **provisioning dell'IPv4 pubblico statico sia completo** sulla mia linea e che l'indirizzo venga assegnato direttamente alla WAN del NeXXt One (non un NAT condiviso);
> 2. Se l'IP pubblico viene fornito tramite NAT 1:1 a monte, verificare che **le connessioni in ingresso siano inoltrate** al mio CPE;
> 3. Verificare che non ci siano **filtri inbound** lato rete sulla mia linea, sia IPv4 sia IPv6.
>
> Resto disponibile per qualsiasi ulteriore verifica tecnica. Grazie.

### 沟通技巧

- 一线客服先用简短版；不解决就要求 **aprire un ticket tecnico**，贴详细版。
- 对方若说"已开通没问题"，顶回去：
  > "Sulla WAN c'è 10.64.23.145, che è un indirizzo privato: l'IP pubblico non è assegnato alla mia linea."
- 关键词：provisioning、CGNAT、NAT 1:1、reprovisioning。
