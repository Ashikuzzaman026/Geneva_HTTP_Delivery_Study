# HTTP File-Verification Plugin

The `filecheck` plugin evaluates complete HTTP delivery within Geneva's
existing test framework. It transfers a deterministic 256 KiB object
and checks response status, object length and SHA-256.

## Delivery checks

A transfer succeeds only when:

- The response status is HTTP 200.
- The received object length and declared Content-Length both match
  the expected reference size.
- Its SHA-256 matches the predefined reference object.
- No transfer error occurs.


The plugin records connection stage, status, received bytes, digest,
timings and errors. Symptom reporting does not use censor identity,
strategy labels or server fault modes. Failure causes remain
undetermined; a reset alone is not treated as proof of censorship.

The server supports normal delivery and four controlled fault modes:
corruption, truncation, HTTP 503 and delayed headers.

## Install

Use the prepared Geneva checkout and existing Docker images.
For the example commands, place this repository at:

```text
$HOME/research/Geneva_HTTP_Delivery_Study
```

For a fresh checkout at the recorded commit, run these commands from
the Geneva directory before installing the plugin. Skip this step
if the local patch is already applied.

```bash
git apply --check "$HOME/research/Geneva_HTTP_Delivery_Study/source_snapshot/local_changes.patch"
git apply "$HOME/research/Geneva_HTTP_Delivery_Study/source_snapshot/local_changes.patch"
```

Install the plugin:

```bash
python3 "$HOME/research/Geneva_HTTP_Delivery_Study/prototype/install_into_geneva.py" \
  "$HOME/research/geneva"
```

The installer adds:

- `geneva_healthcheck.py`
- `plugins/filecheck/client.py`
- `plugins/filecheck/server.py`

It refuses to overwrite differing existing files. It does not modify
Geneva's actions or censors. With the existing bind-mounted checkout
and prepared dependencies, no image rebuild is required.

## Local tests

From this repository's `prototype/` directory:

```bash
python3 -m unittest discover -s tests -v
```


For a standalone loopback demonstration, run these commands in separate
terminals from `prototype/`:

```bash
python3 geneva_healthcheck.py serve --port 18081
```

```bash
python3 geneva_healthcheck.py probe --port 18081
```

## Geneva smoke test

From the prepared Geneva checkout:

```bash
cd "$HOME/research/geneva"
mkdir -p results

log="results/filecheck_smoke_$(date +%Y%m%d_%H%M%S).log"

sudo docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$PWD":"$PWD" \
  -w "$PWD" \
  geneva-runner:local \
  -c 'python evolve.py --eval-only "" --no-skip-empty --test-type filecheck --censor censor2 --bad-word ultrasurf --probe-host benign.example --port 18080 --runs 1 --log debug' \
  > "$log" 2>&1

echo "Docker exit code: $?"
grep -E 'Confirmed server listener|ENDPOINT_RESULT|Overall|Traceback|ERROR:' "$log"
echo "Saved log: $log"
```

The evaluator uses the host Docker daemon and privileged test
containers. Run it in the dedicated research VM.

Inspect readiness, errors and `ENDPOINT_RESULT`; process exit code
or fitness alone does not establish verified delivery. Endpoint records
are saved under:

```text
trials/<timestamp>/endpoint/<environment_id>.json
```

The probe hostname is an HTTP Host header. The connection target is
the local Docker server.

## Recorded experiments


- 24 HTTP comparison trials across two mock censors.
- 12 controlled HTTP fault trials.

Results are recorded in the repository's `data/` directory and research
note. These extend the earlier 24 echo trials; the workloads use
different success criteria and are reported separately.


## Scope

This is a local HTTP evaluation workload. It does not implement causal
censorship attribution, adaptive recovery or a learned classifier.
It does not validate HTTPS or real-world censorship evasion.

## References

- Source baseline: `61a4a5104641ddbba6dd0526013e85a5be875203`
- Geneva source: https://github.com/Kkevsterrr/geneva
- Geneva paper: https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf