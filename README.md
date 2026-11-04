# fabricrca: from host symptom to fabric root cause

Companion code for the article **"From Symptom to Root Cause: AI-Driven Correlation of Host
Multipath Loss with Fabric and Array Events via Local RAG"** (Derek Asir Muthurajan Caleb, 2026).

When a server loses a storage path, the evidence is spread across three systems, each with its
own log format and its own clock:

- the host's multipath layer
- the Fibre Channel switches
- the storage array

`fabricrca` puts all three into one event schema and joins them through the fabric's device map
(initiator WWN to switch port to array port). It retrieves the events around the symptom and
reports the **culprit**, its **precursors** and its **victims**. Every claim cites specific event
ids. It also tells apart cases that look alike, such as a failing switch-side optic and a failing
host HBA, by the *order* in which the evidence appears.

```
host log + multipath -ll + sysfs ─┐
switch logs (rule-driven)        ─┼─> common Event schema ─> time-windowed retrieval (BM25 or LlamaIndex)
array logs  (rule-driven)        ─┘                          ─> hypothesis scoring by evidence order
                                                              ─> cited report (+ optional local LLM, verified)
```

## Quick start

```bash
pip install .                                            # standard library only
fabricrca analyze examples/sfp_failure/case.json         # switch-side optic failure
fabricrca analyze examples/hba_failure/case.json         # genuinely failing host HBA
fabricrca events  examples/sfp_failure/case.json         # the normalised event stream
python -m unittest discover -s tests
```

Report for the SFP case (abridged):

```
Root cause: Physical-layer fault on switch port edge-a 2/3 (target side)
| 03:12:40 | switch: edge-a 2/3       | SW_CRC_THRESHOLD   | precursor        |
| 03:13:58 | switch: edge-a 2/3       | SW_OPTIC_RX_LOW    | **CULPRIT**      |
| 03:14:02 | host: dbhost1 mpatha/sdc | HOST_PATH_FAULT    | symptom (victim) |
| 03:14:03 | switch: edge-a 2/3       | SW_PORT_DOWN       | victim           |
| 03:14:03 | array: ARRAY-01 CTRL-A-2 | ARRAY_PORT_DOWN    | victim           |
- host_hba_fault: no host HBA event, and fabric/array alarms on the path precede the path fault
- array_side_fault: switch-side SW_CRC_THRESHOLD precedes it by 83s
```

In the HBA case, the host firmware error comes first. The switch's port-down event one second
later is correctly classed as a *victim*.

## Using it on your own incident

1. **Host.** Run `multipath -ll > multipath_ll.txt`, then run `scripts/collect_host_info.sh >
   host_info.json` (it reads the sysfs FC classes). Export the kernel and multipathd log for the
   incident window.
2. **Switches and arrays.** Export the logs for the same window. The generic default rules match
   common wording ("port 2/3 rx power ... below threshold", "port 2/3 link down", and so on). For
   your platform's wording, write a rules file like `examples/custom_switch_rules.json`. You can
   also feed JSON-lines events directly.
3. **Topology.** Write `topology.json` from your name-server and array-port inventory.
4. Write a `case.json` that points to all of the above (see `examples/*/case.json`). Use
   `offset_s` to correct any known clock skew per source, then run `fabricrca analyze case.json`.

### Options

| Option | Purpose |
|---|---|
| `--window 600 --after 120` | Retrieval window around the symptom, in seconds |
| `--skew 2` | Clock tolerance used when ordering events |
| `--all` | Analyse every path fault, not just the first |
| `--retriever llamaindex` | Use a LlamaIndex vector store with Ollama embeddings (`pip install ".[rag]"`) |
| `--llm ollama --model qwen2.5:7b` | Ask a local LLM for an explanation too. Its answer is **verified**: cited ids must have been retrieved, and the culprit can't come after its victims |
| `--markdown rca.md --json rca.json` | Save the report |

## Design notes

- **Evidence first.** The deterministic engine decides the culprit from the order and specificity
  of events. The LLM is optional, sees only the retrieved events, and is checked against them. If
  its answer disagrees with the engine, the report says so.
- **Precursors versus victims.** The culprit is the most specific event of the winning hypothesis
  (for example a low optic Rx power alarm). Earlier, less specific events on the same resource
  (for example rising CRC errors) are precursors. Later events on connected endpoints are victims.
- **Limits.** ISL-level and multi-hop causes (for example congestion spreading from another port)
  are not modelled yet. Clocks should be NTP-synchronised, or corrected with `offset_s`.

## Author

**Derek Asir Muthurajan Caleb**: author, owner, and publisher.

This is an independent implementation of the ideas in the article. It contains no proprietary
code, data, event catalogues, message IDs, or schemas from any vendor. The event types and parsing
rules are generic, and all example logs are fictitious.

## License

Apache License 2.0. See [LICENSE](LICENSE).
