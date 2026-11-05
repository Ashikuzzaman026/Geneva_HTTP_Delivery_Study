#!/usr/bin/env bash
# Run from the existing, patched Geneva checkout, in the dedicated research VM.
# Invocation: bash /path/to/package/scripts/run_http_matrix.sh comparison
# or: bash /path/to/package/scripts/run_http_matrix.sh faults
set -u
kind="${1:-comparison}"
case "$kind" in comparison|faults) ;; *) echo 'Choose comparison or faults'; exit 1;; esac
test -f geneva_healthcheck.py || { echo 'Install the prototype and run from the Geneva checkout'; exit 1; }
batch="results/http_${kind}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$batch/source"
cp geneva_healthcheck.py "$batch/source/"
cp plugins/filecheck/client.py "$batch/source/filecheck_client.py"
cp plugins/filecheck/server.py "$batch/source/filecheck_server.py"
git diff > "$batch/source/local_changes.patch"
git rev-parse HEAD > "$batch/source/upstream_commit.txt"
sudo docker image inspect base:latest geneva-runner:local > "$batch/source/image_metadata.json" || exit 1
printf 'censor,condition,trial,server_mode,probe_host,strategy,exit_code,console_log\n' > "$batch/run_manifest.csv"
if [ "$kind" = comparison ]; then
  censors='censor1 censor2'; conditions='benign blocked segment22 segment26'
else
  censors='censor2'; conditions='corrupt truncate status503 delay'
fi
for censor in $censors; do
  for condition in $conditions; do
    probe_host='ultrasurf.example'; strategy=''; mode='normal'
    case "$condition" in
      benign) probe_host='benign.example';;
      segment22) strategy='[TCP:flags:PA]-fragment{tcp:22:True}-|';;
      segment26) strategy='[TCP:flags:PA]-fragment{tcp:26:True}-|';;
      corrupt|truncate|status503|delay) probe_host='benign.example';mode="$condition";;
    esac
    for trial in 1 2 3; do
      if [ "$kind" = comparison ]; then name="${censor}_${condition}_${trial}"; else name="${condition}_${trial}"; fi
      log="$batch/$name.log"
      echo "Starting $name"
      sudo docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
        -v "$PWD":"$PWD" -w "$PWD" geneva-runner:local \
        -c 'python evolve.py --eval-only "$1" --no-skip-empty --test-type filecheck --censor "$3" --bad-word ultrasurf --probe-host "$2" --file-server-mode "$4" --file-server-delay 12 --transfer-timeout 10 --port 18080 --runs 1 --log debug' \
        runner "$strategy" "$probe_host" "$censor" "$mode" > "$log" 2>&1
      status=$?
      echo "$status" > "$batch/$name.exitcode"
      printf '%s,%s,%s,%s,%s,%s,%s,%s\n' "$censor" "$condition" "$trial" "$mode" "$probe_host" "$strategy" "$status" "$log" >> "$batch/run_manifest.csv"
      grep -E 'Confirmed server listener|Packet triggered censor|ENDPOINT_RESULT|Overall|Traceback|ERROR:' "$log" || true
      if [ "$status" -ne 0 ] || grep -qE 'Traceback|ERROR:|Address already in use|ConnectionRefusedError' "$log"; then
        echo "Runtime issue; preserve this trial and review before continuing: $log"
        exit 1
      fi
    done
  done
done
echo "Saved batch: $batch"
