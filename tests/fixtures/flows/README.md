# Flow reference fixtures

- `scenarios.pcap` is generated deterministically by `packet-tools-fixtures`.
- `scenarios.cicflowmeter-9d91f72.csv` was produced from `scenarios.pcap` with ahlashkari/CICFlowMeter commit `9d91f72`.
- `scenarios.corrected-13a0615.csv` was produced from `scenarios.pcap` with GintsEngelen/CICFlowMeter commit `13a0615`.

The CSV files are external reference outputs. The fixture generator must preserve them and must not regenerate or rewrite them.
