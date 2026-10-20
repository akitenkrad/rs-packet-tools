use std::fs;

#[test]
fn median_sorts_values_and_uses_the_middle_pair() {
    assert_eq!(ptbench::median(&[9.0, 1.0, 5.0]), Some(5.0));
    assert_eq!(ptbench::median(&[4.0, 2.0]), Some(3.0));
    assert_eq!(ptbench::median(&[]), None);
}

#[test]
fn scapy_parser_reads_the_full_dissect_line() {
    let output = "raw read      : 100 pkts 0.01s 10,000 pkt/s\n\
full dissect+5tuple: 100 pkts 0.25s 400 pkt/s  flows=12\n";
    let parsed = ptbench::parse_scapy(output).unwrap();
    assert_eq!(parsed.packets, 100);
    assert_eq!(parsed.seconds, 0.25);
    assert_eq!(parsed.pkt_per_sec, 400.0);
}

#[test]
fn sha256sums_parser_matches_full_path_and_basename() {
    let directory = tempfile::tempdir().unwrap();
    let sums = directory.path().join("SHA256SUMS");
    fs::write(
        &sums,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  captures/a.pcap\n\
bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb *b.pcap\n",
    )
    .unwrap();
    let parsed = ptbench::read_sha256sums(&sums).unwrap();
    assert_eq!(parsed["captures/a.pcap"], "a".repeat(64));
    assert_eq!(parsed["b.pcap"], "b".repeat(64));
}

#[test]
fn trial_order_rotates_all_three_engines() {
    assert_eq!(
        ptbench::rotated_order(0),
        ["scapy", "etherparse", "packet-tools"]
    );
    assert_eq!(
        ptbench::rotated_order(1),
        ["etherparse", "packet-tools", "scapy"]
    );
    assert_eq!(
        ptbench::rotated_order(2),
        ["packet-tools", "scapy", "etherparse"]
    );
    assert_eq!(ptbench::rotated_order(3), ptbench::rotated_order(0));
}

#[test]
fn inputs_csv_packet_total_handles_quoted_paths_and_rejects_errors() {
    let ok = "input_id,input,output_dir,packets,status,error\n\
0,\"capture, one.pcap\",\"capture, one.pcap\",12,ok,\n\
1,\"capture \"\"two\"\".pcap\",capture-two.pcap,30,ok,\n";
    assert_eq!(ptbench::packet_total_from_inputs_csv(ok).unwrap(), 42);

    let failed = "input_id,input,output_dir,packets,status,error\n\
0,bad.pcap,bad.pcap,0,error,broken\n";
    assert!(ptbench::packet_total_from_inputs_csv(failed).is_err());
}
