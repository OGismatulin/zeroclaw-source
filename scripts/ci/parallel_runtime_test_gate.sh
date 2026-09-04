#!/usr/bin/env bash

set -euo pipefail

runs="${ZEROCLAW_PARALLEL_TEST_RUNS:-3}"
threads="${ZEROCLAW_PARALLEL_TEST_THREADS:-16}"
scope="${ZEROCLAW_PARALLEL_TEST_SCOPE:-all}"

case "$runs" in
    ''|*[!0-9]*|0)
        echo "ZEROCLAW_PARALLEL_TEST_RUNS must be a positive integer (got: $runs)."
        exit 2
        ;;
esac

case "$threads" in
    ''|*[!0-9]*|0)
        echo "ZEROCLAW_PARALLEL_TEST_THREADS must be a positive integer (got: $threads)."
        exit 2
        ;;
esac

case "$scope" in
    all)
        crates=(zeroclaw-runtime zeroclaw-channels)
        ;;
    channels)
        crates=(zeroclaw-channels)
        ;;
    *)
        echo "ZEROCLAW_PARALLEL_TEST_SCOPE must be 'channels' or 'all' (got: $scope)."
        exit 2
        ;;
esac

# Fork patch #40: one fork test asserts on the PROCESS-GLOBAL runtime-trace
# writer with a 2-entry rolling cap, so any other test in the same process that
# emits a trace event evicts its rows. That is a property of the singleton, not
# a parallelism bug in the code under test, and it is unfixable while the writer
# is global. The test keeps its coverage in the required `Test` job, which runs
# under nextest (process per test); only this redundant in-process rerun skips it.
skips=(
    observability::runtime_trace::tests::legacy_record_event_writes_legacy_shape_and_rolls
)
skip_args=()
for skip in "${skips[@]}"; do
    skip_args+=(--skip "$skip")
done

for crate in "${crates[@]}"; do
    for ((run = 1; run <= runs; run++)); do
        echo "==> parallel runtime regression: $crate run $run/$runs ($threads threads)"
        cargo test --locked --quiet -p "$crate" --lib -- \
            --test-threads="$threads" "${skip_args[@]}"
    done
done
