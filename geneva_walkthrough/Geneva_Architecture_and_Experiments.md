# Geneva Architecture and Experimental Extension

This note connects Geneva's packet-processing architecture to the
local echo and HTTP experiments and the additional file-verification
plugin.

Source baseline: `61a4a5104641ddbba6dd0526013e85a5be875203`

## Architecture

Geneva has three distinct components:

- **Search:** constructs and evolves candidate packet-manipulation strategies.
- **Engine:** applies a strategy to intercepted packets.
- **Evaluator:** measures application outcomes and assigns fitness.

The experiments used the existing engine and evaluator with manually
selected strategies through `--eval-only`. Genetic strategy discovery
was not run.

## Strategy representation

A strategy contains outbound and inbound forests separated by `\/`.
Each tree combines a packet trigger with an action tree.

```text
[TCP:flags:PA]-fragment{tcp:26:True}-| \/
```

This strategy matches outbound packets with TCP flags `PA` and segments
their TCP payload at byte 26, emitting the first segment first. Its
inbound forest is empty. Nonmatching packets pass through.

The four primitive action families are duplicate, fragment, tamper and
drop. Actions can produce packets for subsequent branches or discard
them. When multiple trees match, each operates on a fresh copy of the
original packet rather than receiving the previous tree's output.

| Component | Source |
|---|---|
| Strategy parsing | `actions/utils.py`: `parse` |
| Trigger matching | `actions/trigger.py`: `Trigger.is_applicable` |
| Direction and forest execution | `actions/strategy.py`: `Strategy.act_on_packet`, `run_on_packet` |
| Action-tree execution | `actions/tree.py`: `ActionTree.run`, `do_run` |
| TCP segmentation | `actions/fragment.py`: `FragmentAction.tcp_segment` |
| Packet interception | `engine.py`: `out_callback`, `handle_packet`, `in_callback` |

The offline walkthrough exercises selected transformations and records
source locations and file hashes. It does not cover every strategy
feature or execute the search process.

## Why compare split22 and split26?

The request begins:

```text
GET / HTTP/1.1\r\nHost: ultrasurf.example...
```

The hostname starts after 22 bytes.

- **split22:** the second segment contains the complete keyword `ultrasurf`.
- **split26:** the keyword is divided into `ultr` and `asurf`.

Both transformations should preserve the application byte stream.
For an initial TCP sequence number of 1000, split26 produces segments
starting at 1000 and 1026. The walkthrough checks payload lengths,
sequence offsets, exact reconstruction and keyword placement.

The two mock censors inspect keywords within tracked packet payloads
without reconstructing the complete application stream. Dividing the
keyword can therefore avoid their keyword check. This observation
does not establish effectiveness against stream-reassembling censors.

## Search and application fitness

The source implements traffic collection, population initialization,
mutation, crossover, fitness evaluation, tournament selection and
candidate retention.

| Stage | Entry point in `evolve.py` |
|---|---|
| Traffic collection | `run_collection_phase` |
| Population initialization | `initialize_population` |
| Mutation and crossover | `mutation_crossover` |
| Candidate evaluation | `fitness_function` |
| Selection | `selection_tournament` |
| Candidate retention | `add_to_hof`, `genetic_solve` |
| Supplied-strategy evaluation | `eval_only` |

Fitness depends on the application's success criterion and subsequent
penalties. A strategy's score therefore reflects the workload used
to evaluate it.

This study used one evaluation per invocation and three separate
invocations per condition. It did not reproduce the paper's genetic
search configuration, convergence results or field deployments.

## Experiments and observations

The study contains:

- 24 final echo trials.
- 24 final HTTP comparison trials.
- 12 controlled HTTP fault trials.

Local echo-harness corrections addressed stream handling,
partial-success scoring and a server-readiness race. Geneva's packet
actions and mock censor implementations were unchanged.

Against the reset-based censor, split22 completed five exact echo
exchanges in each of three trials but failed HTTP delivery in all
three trials. Split26 succeeded in both workloads against both
mock censors.

In the echo captures, reset sequence numbers lagged previously
observed server data. In the HTTP captures, the first reset arrived
before server payload and matched the latest captured client ACK.

These observations support a timing/sequence explanation but do not
isolate one causal factor or directly reveal the kernel's reset
validation decision. Sequence analysis uses decoded PCAP fields,
not the checksum displayed in Geneva's packet log.

## File-verification extension

The additional `filecheck` plugin uses Geneva's existing evaluation
interface to transfer a deterministic 256 KiB HTTP object.

Successful delivery requires:

1. HTTP status 200.
2. Exact expected object length.
3. SHA-256 matching the predefined reference object.
4. No transfer error.

The reference digest is specified independently of the server response.
This checks the received object's integrity; it does not authenticate
arbitrary Internet content.

The plugin records connection stage, response status, received bytes,
digest, timing and errors. Its symptom rules do not receive censor
identity, strategy labels or server fault modes.

Controlled corruption, truncation, HTTP 503 and delayed-header trials
checked the delivery policy. These tests establish behavior on the
constructed cases, not general diagnostic accuracy. Resets, closes
and timeouts remain observations; their underlying cause is not inferred.

## Proposed next study

The results motivate a question: when a strategy succeeds under one
workload, what additional evaluation is needed before relying on it
under another?

A controlled follow-up would:

1. Hold request bytes, response size and segmentation constant while
   varying response timing.
2. Vary individual workload dimensions and measure verified delivery.
3. Compare single probes with matched benign and keyword-bearing probes,
   recording their information gain and cost.

The fixed split26 strategy should remain a baseline because it already
succeeds in this pilot. Adaptive selection offers no demonstrated
advantage in the current results.

The proposed study concerns workload transfer and evaluation methodology.
Its novelty and practical value require related-work assessment and
feedback on a suitable deployment scenario.

## Attribution and limitations

Geneva's architecture, search algorithms and packet primitives are
credited to its authors. This study adds local harness corrections,
a file-verification workload and supporting analysis; 

The evidence is limited to one VM, two simplified censors, three
repeats per condition and a fixed reference object. It does not
establish real-world effectiveness, causal censorship attribution
or adaptive recovery.

## References

- Geneva source: https://github.com/Kkevsterrr/geneva
- Geneva paper: https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf
