use std::collections::BTreeMap;

use packet_tools_reassembly::{FragmentBuffer, IpPolicy, TcpPolicy, TcpSegmentBuffer};
use serde::Deserialize;

#[derive(Deserialize)]
struct IpVectors {
    ipv4_fragments: Vec<Fragment>,
    ipv6_fragments: Vec<Fragment>,
    expected: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Deserialize)]
struct Fragment {
    offset: usize,
    more_fragments: bool,
    fill: char,
    len: usize,
}

#[test]
fn sturges_novak_ip_vectors_cover_all_twelve_policy_and_version_pairs() {
    let vectors: IpVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reassembly/sturges_novak_ip.json"
    ))
    .unwrap();

    for (policy_name, versions) in &vectors.expected {
        let policy: IpPolicy = policy_name.parse().unwrap();
        for (version, fragments) in [
            ("ipv4", &vectors.ipv4_fragments),
            ("ipv6", &vectors.ipv6_fragments),
        ] {
            let mut buffer = FragmentBuffer::new(policy);
            for (index, fragment) in fragments.iter().enumerate() {
                let fill = u8::try_from(fragment.fill as u32).unwrap();
                let result = buffer.insert(
                    fragment.offset,
                    fragment.more_fragments,
                    &vec![fill; fragment.len],
                    index as u64,
                );
                if index < 9 {
                    assert!(
                        result.events.is_empty(),
                        "{policy_name}/{version} fragment {index}"
                    );
                }
                if index + 1 < fragments.len() {
                    assert!(
                        result.complete.is_none(),
                        "{policy_name}/{version} completed early"
                    );
                } else {
                    let actual = result.complete.expect("last fragment completes payload");
                    let expected = versions[version]
                        .bytes()
                        .flat_map(|byte| std::iter::repeat_n(byte, 8))
                        .collect::<Vec<_>>();
                    assert_eq!(actual, expected, "{policy_name}/{version}");
                    assert!(buffer.overlap_count() > 0, "{policy_name}/{version}");
                    assert!(buffer.conflict_count() > 0, "{policy_name}/{version}");
                }
            }
        }
    }
}

#[derive(Deserialize)]
struct TcpVectors {
    cases: Vec<TcpCase>,
}

#[derive(Deserialize)]
struct TcpCase {
    name: String,
    policy: String,
    steps: Vec<TcpStep>,
}

#[derive(Deserialize)]
struct TcpStep {
    rel_seq: u32,
    data: String,
    expected: String,
}

#[test]
fn sturges_novak_tcp_vectors_cover_all_seventy_two_policy_case_and_isn_pairs() {
    let vectors: TcpVectors = serde_json::from_str(include_str!(
        "../../../tests/fixtures/reassembly/sturges_novak_tcp.json"
    ))
    .unwrap();
    assert_eq!(vectors.cases.len(), 24);

    for case in &vectors.cases {
        let policy: TcpPolicy = case.policy.parse().unwrap();
        for isn in [0, 1, u32::MAX] {
            let mut buffer = TcpSegmentBuffer::new(policy, isn);
            for (index, step) in case.steps.iter().enumerate() {
                buffer.insert(
                    isn.wrapping_add(step.rel_seq),
                    step.data.as_bytes(),
                    index as u64,
                );
                assert_eq!(
                    buffer.render(step.expected.len(), b'.'),
                    step.expected.as_bytes(),
                    "{} ISN={isn} step={index}",
                    case.name
                );
            }
        }
    }
}

#[test]
fn tcp_policy_aliases_are_stable() {
    for alias in ["windows", "macos", "hpux10", "irix"] {
        assert_eq!(alias.parse::<TcpPolicy>().unwrap(), TcpPolicy::Bsd);
    }
    assert_eq!("hpux11".parse::<TcpPolicy>().unwrap(), TcpPolicy::Solaris);
    assert_eq!("vista".parse::<TcpPolicy>().unwrap(), TcpPolicy::First);
    assert_eq!(
        "old_linux".parse::<TcpPolicy>().unwrap(),
        TcpPolicy::OldLinux
    );
    assert_eq!(
        "old-linux".parse::<TcpPolicy>().unwrap(),
        TcpPolicy::OldLinux
    );
}

#[test]
fn corrected_ptacek1998_equal_range_ambiguity_follows_each_target_policy() {
    for (name, expected) in [
        ("first", b"\x8f\x97\x99".as_slice()),
        ("bsd", b"\x8f\x97\x99".as_slice()),
        ("windows", b"\x8f\x97\x99".as_slice()),
        ("solaris", b"\x8f\x97\x99".as_slice()),
        ("linux", b"phf".as_slice()),
        ("last", b"phf".as_slice()),
    ] {
        let mut buffer = FragmentBuffer::new(name.parse().unwrap());
        buffer.insert(0, true, &[0x8f, 0x97, 0x99], 0);
        buffer.insert(0, true, b"phf", 1);
        let result = buffer.insert(3, false, b"!", 2);
        assert_eq!(&result.complete.unwrap()[..3], expected, "IP {name}");
    }

    for (name, expected) in [
        ("first", b"\x8f\x97\x99".as_slice()),
        ("bsd", b"\x8f\x97\x99".as_slice()),
        ("linux", b"\x8f\x97\x99".as_slice()),
        ("old-linux", b"phf".as_slice()),
        ("solaris", b"phf".as_slice()),
        ("last", b"phf".as_slice()),
    ] {
        let mut buffer = TcpSegmentBuffer::new(name.parse().unwrap(), 100);
        buffer.insert(101, &[0x8f, 0x97, 0x99], 0);
        buffer.insert(101, b"phf", 1);
        assert_eq!(buffer.render(3, b'.'), expected, "TCP {name}");
    }
}

#[test]
fn sparse_buffers_charge_ranges_instead_of_sequence_space_or_individual_bytes() {
    let mut fragments = FragmentBuffer::new(IpPolicy::Bsd);
    fragments.insert(60_000, true, &vec![b'x'; 1_500], 1);
    assert_eq!(fragments.interval_count(), 1);
    assert!(fragments.allocated_bytes() < 2_048);

    let mut stream = TcpSegmentBuffer::new(TcpPolicy::Bsd, 0);
    stream.insert(1_000_001, &vec![b'y'; 32_768], 2);
    assert_eq!(stream.interval_count(), 1);
    assert!(stream.allocated_bytes() <= 33_024);
}
