# Fastweb 网络侧调查结果（私网 WAN、上游 NAT 与 6rd）

> 这份笔记回答一个反复出现的问题："我的设备已经 root 了，为什么外网还是连不进来？"
> 结论先行：私网 WAN 能证明存在上游 NAT，但**不能单独证明入站被堵**。Fastweb 可以在
> CPE 地址不变的情况下配置静态 1:1 NAT 并开放入站。地址分配与入站可达性必须分开记录，
> 后者以真实连接时的计数器、conntrack 或抓包为准。

## 1. IPv4：私网 WAN 可能对应多种上游状态

- 客服确认账户"已开通静态公网 IPv4"，出站查询也确实显示一个公网地址。
- 但 CPE 的 WAN 接口上配置的是**私网地址**（示例：`10.64.23.145/22`，网关 `10.64.20.1`），
  强制 DHCP 重新协商后依然如故。
- 意大利社区有完全一致的案例：静态 IP"已开通"但 CPE 拿不到，最终要靠 Fastweb 后台
  **reprovisioning** 解决（客服原话 "CPE non NAT444 - Reprovisioning non previsto"）。
- 当时从外网新建连接时，CPE 防火墙计数与抓包均无变化，只能证明**该次测试窗口内**包没有到达。
  它不能证明线路永远不可入站：Fastweb 可以在不改变私网 WAN 租约的情况下调整上游 provisioning，
  提供静态 1:1 映射并开放入站。

## 2. IPv6：6rd 入站同样必须实测

- Fastweb 住宅宽带的 IPv6 走 **6rd 隧道**（DHCPv4 option 212 下发参数），LAN 得到
  `2001:b07:xxxx:xxxx::/64` 前缀。前缀内嵌的就是 WAN 的 IPv4：
  示例前缀 `...:a40:1791::/64` → 字节 `10.64.23.145`（0a=10, 40=64, 17=23, 91=145），即当前私网 WAN 地址。
- 出站 IPv6 完全正常（CPE → 6rd BR anycast 81.208.50.214）。
- 入站实测：用外部 IPv6 TCP 扫描服务对 CPE 下游主机的全局地址发起连接，
  同时在 CPE 上 tcpdump：**v6 SYN 与 6rd 封装包（proto 41）均为零**，而扫描器收到
  "Connection refused"（Fastweb 网内设备代答的 ICMP 不可达）。
- 该测试窗口的结论是 6rd 入站在上游被终结或无路由。后续 provisioning 改变后，WAN IPv4
  仍为私网，但已有公网 IPv6 入站到达 CPE 的证据。因此这是可变化的运营商状态，不能从地址永久推断。

## 3. 这意味着什么

| 层面 | 能做/不能做 |
|---|---|
| CPE/内网 | 分别核对监听、DNAT 和精确防火墙规则 |
| 运营商网内 | 私网 WAN 说明有上游 NAT；入站策略在实测前保持未知 |
| 客户端侧 | 在网关观察期间从外部新建连接，不能用旧连接或单纯端口扫描猜测 |

**可行出路：**

1. 运行 `nexxt inbound observe --rule 名称 --key 私钥`，并在窗口内从外网新建连接。
   正增量证明包到达网关；零增量只是不确定，不能直接写成“被堵”。
2. 请 Fastweb 核对静态公网 IP / 上游 1:1 NAT provisioning 与入站过滤。只要映射静态且
   正确转发，公网地址不一定需要直接出现在 WAN 接口。
3. **VPS 中继**：出站链路正常时，让内网设备主动连一台有公网 IP 的 VPS
   建隧道，外部客户端连 VPS 中转。不受 Fastweb 任何限制。

## 4. 给 Fastweb 的话术（意大利语）

### 简短版（在线客服）

> Buongiorno, ho bisogno di aiuto con il mio **IP pubblico statico**, che secondo la vostra assistenza è già attivo sul mio account.
>
> Sulla WAN del mio NeXXt One c'è un **indirizzo privato: 10.64.23.145/22** (gateway 10.64.20.1), anche dopo un rinnovo DHCP forzato. Capisco che l'IP pubblico possa essere fornito tramite NAT 1:1 a monte, ma durante le mie prove le nuove connessioni in ingresso non hanno incrementato i contatori del CPE.
>
> Potete verificare il **provisioning dell'IP pubblico statico**, specificando se è assegnato direttamente o tramite NAT 1:1, e controllare che il traffico in ingresso venga inoltrato al mio CPE?

### 详细版（工单/邮件）

> **Oggetto: IP pubblico statico non assegnato alla WAN del CPE – richiesta verifica provisioning**
>
> Buongiorno,
>
> sono un cliente Fastweb con connessione FTTH e gateway **NeXXt One (FGA221D)**. L'assistenza mi ha confermato che sul mio account è attivo un **indirizzo IPv4 pubblico statico**, ma l'indirizzo non risulta assegnato alla mia linea. Di seguito i fatti tecnici verificati:
>
> 1. La WAN del NeXXt One ha l'indirizzo **10.64.23.145/22** (gateway 10.64.20.1), cioè un indirizzo privato dietro NAT a monte. Un rinnovo DHCP forzato non cambia l'assegnazione.
> 2. L'indirizzo pubblico visibile in uscita è **93.x.x.x**. Vorrei sapere se è configurato come NAT condiviso o NAT statico 1:1; durante le prove indicate sotto non ho osservato nuovi pacchetti in ingresso sul CPE.
> 3. Ho configurato correttamente il port forwarding (UDP 51820 verso un host interno) e verificato che il firewall del CPE non è la causa: **i pacchetti in ingresso non arrivano proprio al CPE** (verificato con contatori firewall e tcpdump sul gateway).
> 4. Anche IPv6 ha lo stesso problema: il prefisso 6rd assegnatomi (**2001:b07:a40:1791::/64**) incorpora proprio l'IPv4 privato 10.64.23.145, e i pacchetti IPv6 in ingresso (inclusi quelli incapsulati 6rd, protocollo 41) **non raggiungono mai il CPE**.
>
> **Cosa chiedo:**
>
> 1. Verificare che il **provisioning dell'IPv4 pubblico statico sia completo** sulla mia linea, tramite assegnazione diretta oppure NAT statico 1:1 non condiviso;
> 2. Se l'IP pubblico viene fornito tramite NAT 1:1 a monte, verificare che **le connessioni in ingresso siano inoltrate** al mio CPE;
> 3. Verificare che non ci siano **filtri inbound** lato rete sulla mia linea, sia IPv4 sia IPv6.
>
> Resto disponibile per qualsiasi ulteriore verifica tecnica. Grazie.

### 沟通技巧

- 一线客服先用简短版；不解决就要求 **aprire un ticket tecnico**，贴详细版。
- 对方若说“已开通”，继续确认它是 WAN 直配还是上游静态 1:1 NAT，并要求核对入站策略。
- 关键词：provisioning、CGNAT、NAT 1:1、reprovisioning。
