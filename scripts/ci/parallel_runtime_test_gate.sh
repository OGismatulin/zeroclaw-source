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
# Adding a skip? `parallel_runtime_test_scope.test.sh` asserts the exact cargo
# argv this script emits — update its expected strings in the same commit.
skips=(
    observability::runtime_trace::tests::legacy_record_event_writes_legacy_shape_and_rolls
    # Same singleton, second victim (2026-09-07): this test re-points the global
    # writer to a temp file with a 50-row rolling cap and asserts exactly one
    # mcp_connect_failure row. In-process neighbours both evict rows through
    # that cap and re-point the writer under a DIFFERENT test lock
    # (`zeroclaw_log::__private_test_writer_lock` vs `TRACE_TEST_LOCK`), so the
    # row lands elsewhere and the count reads 0. Covered by the nextest `Test` job.
    tools::scoped::tests::assemble_emits_one_mcp_connect_failure_per_failed_boot_connect
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
