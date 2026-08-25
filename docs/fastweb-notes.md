# Fastweb network findings (CGNAT & 6rd inbound filtering)

> This note answers the question that comes up again and again: "I have root
> on my gateway — why can't anything from the internet reach my network?"
> Short answer: **it is not your device; Fastweb blocks inbound on both
> stacks.** Evidence and reasoning below. 中文版: [fastweb-notes.zh-CN.md](fastweb-notes.zh-CN.md)

## 1. IPv4: nominally public, actually CGNAT

- Support confirms the account has a "static public IPv4", and outbound
  checks indeed show a public address.
- But the CPE's WAN interface holds a **private address** (measured
  `10.64.23.145/22`, gateway `10.64.20.1` — example values, same pattern),
  and a forced DHCP renegotiation changes nothing.
- Italian community reports describe the exact same situation: the static IP
  is "active" yet never reaches the CPE until Fastweb completes the backend
  **reprovisioning** (a ticket was closed with "CPE non NAT444 -
  Reprovisioning non previsto").
- Conclusion: the public address is only the upstream NAT's egress mapping.
  **Inbound packets never reach the CPE**, no matter how correct the port
  forwarding on the device is.

## 2. IPv6: 6rd works outbound, inbound never crosses the CPE

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
- Conclusion: **6rd inbound is terminated/unrouted inside Fastweb's
  network.** Root cause: 6rd requires a "real routable IPv4"; under CGNAT
  it is inherently broken.

## 3. What this means

| Layer | Can / can't |
|---|---|
| CPE / LAN | Everything is already configured (listeners, precise firewall pinholes); nothing left to improve |
| ISP network | Inbound blocked on both stacks; root on the CPE cannot reach this |
| Client side | Needs IPv6 for the v6 path (enable IPv4/IPv6 dual-stack in the phone's APN) |

**Viable ways out:**

1. **Get Fastweb to complete the static public IPv4 provisioning** (the real
   fix). Once a public IPv4 is assigned to the WAN, the 6rd prefix is
   regenerated embedding the new public address, and inbound IPv6 will
   most likely start working too — zero changes needed on the CPE.
   A ready-to-send message for support is below.
2. **VPS relay** (works today): outbound is fully functional, so a device in
   your LAN can dial out to a VPS with a public IP and external clients
   connect via the VPS. Unaffected by Fastweb's inbound filtering.

## 4. Message for Fastweb support (Italian)

### Short version (live chat)

> Buongiorno, ho bisogno di aiuto con il mio **IP pubblico statico**, che secondo la vostra assistenza è già attivo sul mio account.
>
> Il problema: sulla WAN del mio NeXXt One c'è ancora un **indirizzo privato: 10.64.23.145/22** (gateway 10.64.20.1), anche dopo un rinnovo DHCP forzato. Di conseguenza **nessuna connessione in ingresso raggiunge il mio CPE**, né su IPv4 (ho configurato il port forwarding), né su IPv6 (il prefisso 6rd incorpora proprio l'IPv4 privato).
>
> Potete verificare e **completare il provisioning dell'IP pubblico statico sulla mia linea**, in modo che l'indirizzo pubblico venga assegnato direttamente alla WAN del NeXXt?

### Detailed version (ticket / email)

> **Oggetto: IP pubblico statico non assegnato alla WAN del CPE – richiesta verifica provisioning**
>
> Buongiorno,
>
> sono un cliente Fastweb con connessione FTTH e gateway **NeXXt One (FGA221D)**. L'assistenza mi ha confermato che sul mio account è attivo un **indirizzo IPv4 pubblico statico**, ma l'indirizzo non risulta assegnato alla mia linea. Di seguito i fatti tecnici verificati:
>
> 1. La WAN del NeXXt One ha l'indirizzo **10.64.23.145/22** (gateway 10.64.20.1), cioè un **indirizzo privato/CGNAT**, non quello pubblico. Un rinnovo DHCP forzato (riavvio dell'interfaccia WAN) non cambia l'assegnazione.
> 2. L'indirizzo pubblico visibile in uscita è **93.x.x.x**（il vostro IP pubblico）, ma risulta solo un NAT in uscita: **nessuna connessione in ingresso raggiunge il CPE**.
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

### Communication tips

- Start with the short version in live chat; if the first-line agent can't
  help, ask them to **aprire un ticket tecnico** and paste the detailed one.
- If they reply "it's already active", counter with:
  > "Sulla WAN c'è 10.64.23.145, che è un indirizzo privato: l'IP pubblico non è assegnato alla mia linea."
- Keywords they understand: provisioning, CGNAT, NAT 1:1, reprovisioning.
