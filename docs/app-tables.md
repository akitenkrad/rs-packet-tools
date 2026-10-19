**English** | [日本語](app-tables.ja.md)

# Application tables

Every protocol table begins with these columns:

| Column | Type | Meaning |
|---|---|---|
| `flow_uid` | UInt64 | Stable bidirectional flow identifier |
| `stream_id` | UInt64, nullable | TCP connection identifier; null for UDP |
| `index`, `ts_ns` | UInt64, Int64 | Packet and timestamp that supplied the event's final byte |
| `direction` | Utf8 | `client_to_server` or `server_to_client` |
| `client_ip`, `server_ip` | Utf8 | Connection endpoints |
| `client_port`, `server_port` | UInt16 | Connection ports |
| `transport` | Utf8 | `tcp` or `udp` |

Vector-valued fields use a JSON array string in both CSV and Parquet, preserving one schema across formats.

| Table | Additional columns |
|---|---|
| `dns` | `id`, `is_response`, `opcode`, `rcode`, `aa`, `tc`, `rd`, `ra`, `qname`, `qtype`, `qclass`, `question_count`, `answer_count`, `authority_count`, `additional_count`, `answers`, `malformed` |
| `http` | `transaction`, `kind`, `method`, `uri`, `version`, `host`, `user_agent`, `referer`, `content_type`, `content_length`, `transfer_encoding`, `status`, `reason`, `body_len` |
| `tls` | `kind`, `record_version`, `client_version`, `selected_version`, `supported_versions`, `sni`, `alpn`, `cipher_suites`, `selected_cipher`, `extensions`, `ja3`, `ja3_md5`, `ja4`, `ja3s`, `ja3s_md5` |
| `tls_heartbeat` | `record_version`, `record_length`, `encrypted`, `heartbeat_type`, `declared_payload_length`, `length_mismatch` |
| `ftp` | `kind`, `command`, `argument`, `code`, `text`, `login` |
| `ssh` | `kind`, `proto_version`, `software`, `comments`, `kex_algorithms`, `host_key_algorithms`, `encryption_c2s`, `encryption_s2c`, `mac_c2s`, `mac_s2c`, `compression_c2s`, `compression_s2c` |
| `smtp` | `kind`, `command`, `argument`, `code`, `text`, `body_len` |
| `telnet` | `kind`, `negotiation`, `line`, `truncated` |

DNS `answers` contains readable `TYPE value` strings. HTTP `transaction` numbers requests in connection order and gives the matching response the same number. `body_len` is decoded body length, not chunk framing. TLS handshake versions and cipher suites are unsigned wire values; a complete ClientHello or ServerHello that cannot be decoded is retained with `kind=malformed`. Heartbeat mismatch uses the plaintext capacity `record_length - 3 - 16`; payload details are null after encryption begins. FTP multiline replies join their text with newlines. SMTP DATA omits the terminator and reports only its byte count. Telnet removes IAC commands from text and splits lines at 1,024 bytes.

`dispatch` has `stream_id`, `flow_uid`, endpoints, `protocol`, `probe_direction`, `probe_bytes`, and `stop_reason`. `protocol` includes `unknown`. `stop_reason` also records probe abandonment or parser resynchronization caused by the application memory limit.
