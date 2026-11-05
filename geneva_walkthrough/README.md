# Geneva Packet Walkthrough

This script checks selected Geneva packet transformations using synthetic
packets. It covers TCP segmentation, trigger matching, directional behavior,
duplication, dropping and header modification. It does not transmit packets
or run genetic search.

## Files

- `Geneva_Architecture_and_Experiments.md`: architecture and source-code mapping.
- `walkthrough_geneva.py`: executable checks.
- `walkthrough_result.json`: recorded results and source locations.

## Validation

All ten checks passed against Geneva commit
`61a4a5104641ddbba6dd0526013e85a5be875203`.

The script prepopulates `ACTION_CACHE` with the four tested primitive
classes to avoid constructing `TraceAction`, which opens a raw socket.
Dynamic action discovery and `TraceAction` are outside the test scope.
Search functions are indexed but not executed.

## Run in the prepared VM

Place the extracted package at `$HOME/research/Geneva_HTTP_Delivery_Study`.
From the existing Geneva checkout, run:

```bash
cd "$HOME/research/geneva"

sudo docker run --rm \
  -v "$PWD":"$PWD" \
  -v "$HOME/research/Geneva_HTTP_Delivery_Study/geneva_walkthrough":/walkthrough:ro \
  -w "$PWD" \
  geneva-runner:local \
  -c 'python /walkthrough/walkthrough_geneva.py --output results/geneva_walkthrough.json'
```

No Docker socket mount or privileged container is required.

Expected summary:

```text
Checks passed: 10/10
```

The command saves a new result to `results/geneva_walkthrough.json`
in the Geneva checkout.
