# Application fixture

`scenarios.pcap` is generated deterministically by `packet-tools-fixtures`. It covers UDP and TCP DNS, compressed names and a pointer loop, pipelined and chunked HTTP, HEAD and 304 responses, HTTP recovery after a leading byte, independent midstream probing after one direction reaches 64 KiB, a split ClientHello on TCP port 444, a ServerHello without extensions, a malformed ServerHello, two Heartbeat records in one packet, FTP multiline replies and gap recovery, SSH identification and KEXINIT, SMTP DATA, and character-at-a-time Telnet with IAC negotiation.

The expected values were checked with tshark 4.6.9 using:

```sh
tshark -r scenarios.pcap -d tcp.port==18080,http \
  -Y 'http.request' -T fields -E separator='|' \
  -e frame.number -e http.request.method -e http.request.uri -e http.host -e http.user_agent

tshark -r scenarios.pcap -Y 'dns' -T fields -E separator='|' \
  -e frame.number -e dns.id -e dns.qry.name -e dns.flags.response

tshark -r scenarios.pcap -Y 'tls.handshake.type == 1' -T fields -E separator='|' \
  -e frame.number -e tls.handshake.ja3_full -e tls.handshake.ja3 \
  -e tls.handshake.ja4 -e tls.handshake.extensions_server_name \
  -e tls.handshake.extensions_alpn_str

tshark -r scenarios.pcap -d tcp.port==445,tls \
  -Y 'tls.handshake.type == 2' -T fields -E separator='|' \
  -e frame.number -e tls.handshake.version -e tls.handshake.session_id_length \
  -e tls.handshake.ciphersuite -e tls.handshake.comp_method

tshark -r scenarios.pcap -Y 'tls.record.content_type == 24' -T fields \
  -e frame.number -e ip.src -e ip.dst -e tls.record.length
```

The ClientHello produces JA3 full `771,4865-4866-49199,0-43-16-10-11-13,29-23,0`, JA3 MD5 `6e1af6b5647821abd1be17a68c689990`, and JA4 `t13d0306h2_40b44b994229_fb71836bce29`.
