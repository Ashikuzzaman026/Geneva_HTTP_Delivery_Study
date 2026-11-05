# Evaluating Geneva Beyond Echo: Verifying HTTP File Delivery

This study examines whether Geneva strategies that succeed in an echo
test also preserve complete HTTP file delivery. It combines local
strategy evaluation, packet-level analysis and a file-verification
plugin that checks response status, object length and SHA-256.

The experiments use Geneva's existing engine and evaluator with
manually selected strategies. Genetic search was not run.

## Main result

Each condition was tested three times. Echo success required five
exact exchanges; HTTP success required status 200, the complete
256 KiB reference object and a matching SHA-256.

| Condition | Echo/drop | Echo/reset | HTTP/drop | HTTP/reset |
|---|---:|---:|---:|---:|
| Benign, no strategy | 3/3 | 3/3 | 3/3 | 3/3 |
| Forbidden, no strategy | 0/3 | 0/3 | 0/3 | 0/3 |
| Forbidden, split22 | 0/3 | 3/3 | 0/3 | 0/3 |
| Forbidden, split26 | 3/3 | 3/3 | 3/3 | 3/3 |

Split22 succeeded in echo but failed in HTTP against the reset-based
mock censor. Packet captures support a timing/sequence explanation,
but the causal factor was not isolated.

Twelve additional HTTP fault trials tested corruption, truncation,
HTTP 503 and delayed headers. None was accepted as verified delivery.

## Implementation

The additional `filecheck` plugin:

- Transfers and verifies a deterministic HTTP reference object.
- Records status, bytes, digest, timings and transport errors.
- Reports observable failure symptoms without inferring censorship.

Local harness corrections addressed echo stream handling, scoring
and server readiness. Geneva's packet actions and mock censors
were unchanged.

## Documentation

- [Research note](Geneva_Application_Aware_Research_Note.pdf):
  results, limitations and proposed next study.
- [Architecture and experiments](geneva_walkthrough/Geneva_Architecture_and_Experiments.md):
  Geneva mechanisms and their connection to this study.
- [Packet walkthrough](geneva_walkthrough/README.md):
  offline checks using original Geneva functions.
- [Plugin setup and tests](prototype/README.md):
  installation, local tests and a Geneva smoke test.

Trial summaries are in `data/`; packaged logs and selected packet
captures are in `raw/`. The original echo archive is in `echo_baseline/`.

## Reproduction

Source baseline: `61a4a5104641ddbba6dd0526013e85a5be875203`

The recorded integration experiments used Python 3.6 and the
`base:latest` and `geneva-runner:local` Docker images. Runtime details
are in `source_snapshot/python_environment.txt`; captured Dockerfiles
are in `environment/`.

Follow the plugin setup instructions before running these commands
from the prepared Geneva checkout. Replace `/path/to/package`
with the repository's actual location.

```bash
bash /path/to/package/scripts/run_http_matrix.sh comparison
bash /path/to/package/scripts/run_http_matrix.sh faults
```

The packaged scripts were syntax-checked; the recorded trials used
the original commands. Legacy dependencies are not fully pinned.

## Scope and proposed next study

These results cover one VM, two simplified censors and three repeats
per condition. They do not establish Internet effectiveness or causal
censorship attribution.

The next question is how to validate strategy transfer across workloads.
A controlled follow-up would isolate response timing, vary workload
dimensions and assess the additional evidence obtained from matched
benign and keyword-bearing probes.

Would this approach address a useful Geneva deployment problem,
and which workload or scenario should be prioritized?

## Evidence coverage

`data/packaged_evidence_index.csv` maps the 36 HTTP trials to their
packaged console logs and endpoint records. Original audit CSVs retain
the archive paths; packaged timestamp directories use underscores
for Windows compatibility.

The complete HTTP evidence archive is separate. Its hash is recorded
in `data/input_archives.json`; a complete re-audit requires that archive.

## Attribution

Geneva's architecture, algorithms and packet primitives are credited
to its authors. Contribution and assistance details are documented
in the research note.

## References

- [Geneva source](https://github.com/Kkevsterrr/geneva)
- [Geneva paper](https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf)