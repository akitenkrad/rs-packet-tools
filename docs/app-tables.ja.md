[English](app-tables.md) | **日本語**

# アプリ層の表

各プロトコル表は，次の共通列から始まります．

| 列 | 型 | 内容 |
|---|---|---|
| `flow_uid` | UInt64 | 双方向フローの安定した識別子 |
| `stream_id` | UInt64，null 可 | TCP 接続の識別子．UDP は null |
| `index`，`ts_ns` | UInt64，Int64 | 事象の最後のバイトを運んだ packet とその時刻 |
| `direction` | Utf8 | `client_to_server` または `server_to_client` |
| `client_ip`，`server_ip` | Utf8 | 接続の両端 |
| `client_port`，`server_port` | UInt16 | 接続のポート |
| `transport` | Utf8 | `tcp` または `udp` |

一覧の値は CSV と Parquet の両方で JSON 配列の文字列にし，形式間でスキーマをそろえます．

| 表 | 追加の列 |
|---|---|
| `dns` | `id`，`is_response`，`opcode`，`rcode`，`aa`，`tc`，`rd`，`ra`，`qname`，`qtype`，`qclass`，`question_count`，`answer_count`，`authority_count`，`additional_count`，`answers`，`malformed` |
| `http` | `transaction`，`kind`，`method`，`uri`，`version`，`host`，`user_agent`，`referer`，`content_type`，`content_length`，`transfer_encoding`，`status`，`reason`，`body_len` |
| `tls` | `kind`，`record_version`，`client_version`，`selected_version`，`supported_versions`，`sni`，`alpn`，`cipher_suites`，`selected_cipher`，`extensions`，`ja3`，`ja3_md5`，`ja4`，`ja3s`，`ja3s_md5` |
| `tls_heartbeat` | `record_version`，`record_length`，`encrypted`，`heartbeat_type`，`declared_payload_length`，`length_mismatch` |
| `ftp` | `kind`，`command`，`argument`，`code`，`text`，`login` |
| `ssh` | `kind`，`proto_version`，`software`，`comments`，`kex_algorithms`，`host_key_algorithms`，`encryption_c2s`，`encryption_s2c`，`mac_c2s`，`mac_s2c`，`compression_c2s`，`compression_s2c` |
| `smtp` | `kind`，`command`，`argument`，`code`，`text`，`body_len` |
| `telnet` | `kind`，`negotiation`，`line`，`truncated` |

DNS の `answers` は，読みやすい `TYPE value` の文字列です．HTTP の `transaction` は接続内のリクエスト順で，同じ応答にも同じ番号を付けます．`body_len` は chunk の枠を除いた本文長です．TLS の handshake version と cipher suite は wire 上の符号なし値です．完成した ClientHello または ServerHello を解釈できなかった場合も捨てず，`kind=malformed` として残します．Heartbeat の不一致は平文の容量 `record_length - 3 - 16` で判定し，暗号化後の payload 項目は null です．FTP の複数行応答は改行でつなぎます．SMTP DATA は終端を除き，本文のバイト数だけを残します．Telnet は文字列から IAC を除き，1,024 バイトで行を分けます．

`dispatch` は `stream_id`，`flow_uid`，両端，`protocol`，`probe_direction`，`probe_bytes`，`stop_reason` を持ちます．`protocol` には `unknown` も入ります．`stop_reason` には，アプリ層のメモリ上限による probe の中止や解析器の再同期も残します．
