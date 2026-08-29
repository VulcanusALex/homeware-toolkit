# Fastweb network findings (private WAN, upstream NAT & 6rd)

> This note answers the question that comes up again and again: "I have root
> on my gateway — why can't anything from the internet reach my network?"
> Short answer: a private WAN address shows upstream NAT, but **does not by
> itself prove inbound is blocked**. Fastweb may later provision static 1:1
> NAT while leaving the CPE address private. Measure real inbound traffic and
> treat address assignment and reachability as separate facts. 中文版:
> [fastweb-notes.zh-CN.md](fastweb-notes.zh-CN.md)

## 1. IPv4: a private WAN has more than one possible meaning

- Support confirms the account has a "static public IPv4", and outbound
  checks indeed show a public address.
- But the CPE's WAN interface holds a **private address** (measured
  `10.64.23.145/22`, gateway `10.64.20.1` — example values, same pattern),
  and a forced DHCP renegotiation changes nothing.
- Italian community reports describe the exact same situation: the static IP
  is "active" yet never reaches the CPE until Fastweb completes the backend
  **reprovisioning** (a ticket was closed with "CPE non NAT444 -
  Reprovisioning non previsto").
- At the time of that capture, fresh inbound tests produced no firewall or
  packet-capture evidence at the CPE. That proves the tested flow did not
  arrive **at that time**. It does not prove the line can never receive
  inbound traffic: Fastweb can change upstream provisioning without changing
  the private WAN lease, including a static 1:1 mapping with inbound enabled.

## 2. IPv6: 6rd reachability must also be measured

- Fastweb residential IPv6 is delivered via a **6rd tunnel** (DHCPv4
  option 212). The LAN gets a `2001:b07:xxxx:xxxx::/64` prefix that embeds
  the WAN IPv4: e.g. prefix `...:a40:1791::/64` → bytes `10.64.23.145`
  (0a=10, 40=64, 17=23, 91=145) — the current *private* WAN address.
- Outbound IPv6 works fine (CPE → 6rd border relay anycast 81.208.50.214).
- Inbound test: an external IPv6 TCP scanner connecting to a global address
  of a host behind the CPE, while tcpdump runs on the CPE — **zero v6 SYN
  and zero 6rd-encapsulated (proto 41) packets arrive**, yet the scanner
  receives "Connection refused" (an ICMP unreachable answered by a device
  inside Fastweb's network).
- Conclusion for that test window: 6rd inbound was terminated or unrouted
  upstream. Provisioning later changed and inbound IPv6 was observed reaching
  the CPE even though its WAN IPv4 remained private. Treat this as dynamic
  operator state, not a permanent consequence inferred from the address.

## 3. What this means

| Layer | Can / can't |
|---|---|
| CPE / LAN | Listeners, DNAT and precise firewall pinholes must be verified independently |
| ISP network | Private WAN means upstream NAT; inbound policy remains unknown until measured |
| Client side | Must start a fresh connection while gateway counters or packet capture are observed |

**Viable ways out:**

1. Run `home-gateway inbound observe --rule NAME --key KEY` while starting a new
   external connection. A positive delta proves arrival at the gateway; zero
   is inconclusive and must not be labelled "blocked" without more evidence.
2. Ask Fastweb to verify static-public-IP / 1:1-NAT provisioning and inbound
   filtering. A public address does not have to appear directly on the WAN if
   the upstream mapping is static and forwards inbound correctly.
3. **VPS relay**: outbound is fully functional, so a device in
   your LAN can dial out to a VPS with a public IP and external clients
   connect via the VPS. Unaffected by Fastweb's inbound filtering.

## 4. Message for Fastweb support (Italian)

### Short version (live chat)

> Buongiorno, ho bisogno di aiuto con il mio **IP pubblico statico**, che secondo la vostra assistenza è già attivo sul mio account.
>
> Sulla WAN del mio NeXXt One c'è un **indirizzo privato: 10.64.23.145/22** (gateway 10.64.20.1), anche dopo un rinnovo DHCP forzato. Capisco che l'IP pubblico possa essere fornito tramite NAT 1:1 a monte, ma durante le mie prove le nuove connessioni in ingresso non hanno incrementato i contatori del CPE.
>
> Potete verificare il **provisioning dell'IP pubblico statico**, specificando se è assegnato direttamente o tramite NAT 1:1, e controllare che il traffico in ingresso venga inoltrato al mio CPE?

### Detailed version (ticket / email)

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

### Communication tips

- Start with the short version in live chat; if the first-line agent can't
  help, ask them to **aprire un ticket tecnico** and paste the detailed one.
- If they reply "it's already active", ask whether it is a direct WAN
  assignment or upstream static 1:1 NAT, and request an inbound-policy check.
- Keywords they understand: provisioning, CGNAT, NAT 1:1, reprovisioning.
