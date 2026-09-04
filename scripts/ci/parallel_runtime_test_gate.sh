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

# Fork patch #40: these tests assert on the CONTENT of the process-global
# runtime-trace writer, which cannot be made reliable in an in-process parallel
# run. Two mitigations were tried and are kept because they are correct on their
# own, but neither is sufficient:
#   * a shared install lock — the pollution does not come from installers, it
#     comes from EMITTERS: nearly every test in the crate logs something, and
#     they cannot all be serialized;
#   * per-test markers + flush — they keep foreign rows out, but not another
#     test repointing the writer or setting log_persistence="none"
#     (agent/turn/provider_call.rs does exactly that), which empties the file.
# Coverage stays where it is honest: the required `Test` job runs these under
# nextest, one process per test. Only this redundant in-process rerun skips them.
skips=(
    observability::runtime_trace::tests::legacy_record_event_writes_legacy_shape_and_rolls
    observability::tests::legacy_trace_observer_ignores_llm_response_messages_field
    tools::scoped::tests::assemble_emits_one_mcp_connect_failure_per_failed_boot_connect
    tools::scoped::tests::assemble_emits_no_mcp_connect_failure_on_success
    agent::turn::context_recovery::tests::diagnostic_record_carries_attribution_and_no_message_content
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
