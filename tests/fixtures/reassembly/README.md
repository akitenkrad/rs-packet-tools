# Reassembly test vectors

`sturges_novak_ip.json` and `sturges_novak_tcp.json` contain the inputs and expected values from the Sturges & Novak overlap tests.

The source is the OISF/suricata commit `b717c48` unit tests named `DefragSturgesNovak*` in `src/defrag.c` and `Overlap*` in `src/tests/stream-tcp-list.c`.

These files extract facts only—the test inputs and expected values. They contain no source code.
