#!/bin/sh

RED_C='\033[91;1m'
GREEN_C='\033[92;1m'
END_C='\033[0m'

# Work in process:
# axconfig/rt_axconfig
# task/rt_task
# axtrap/rt_axtrap
# axmount/test_axmount

TESTCASES="
    early_console/rt_early_console
    axlog2/rt_axlog2
    axhal/rt_axhal
    user_stack/rt_user_stack
    driver_block/rt_driver_block
    driver_virtio/rt_driver_virtio
    axmount/rt_axmount
    mutex/rt_mutex
    axalloc/rt_axalloc
    page_table/rt_page_table
    mm/rt_mm
    fstree/rt_fstree
    mmap/rt_mmap
    run_queue/rt_run_queue
    fileops/rt_fileops
    fork/rt_fork
    axfs_ramfs/rt_ramfs
    axdtb/rt_axdtb
    bprm_loader/rt_bprm_loader
    exec/rt_exec
    macrokernel/rt_macrokernel
"

PASSED=0
FAILED=0
FAILURES=

for TEST in $TESTCASES
do
    printf "\n[$TEST]: ...\n\n"

    set -e
    make A=$TEST prepare
    make A=$TEST I=/btp/sbin/hello DUMP_OUTPUT=y run

    set +e
    ret_str=$(cat ${TEST}/expect_output 2>/dev/null)
    if [ -z "${ret_str}" ]; then
        ret_str="\[\S*\]: ok!"
    fi
    #echo "***** ${ret_str}"

    grep -q "${ret_str}" /tmp/output.log
    if [ $? -eq 0 ]; then
        printf "\n[$TEST]: ${GREEN_C}PASSED!${END_C}\n\n"
        PASSED=$(( PASSED + 1 ))
    else
        printf "\n[$TEST]: ${RED_C}FAILED!${END_C}\n\n"
        FAILED=$(( FAILED + 1 ))
        FAILURES="\n${TEST}${FAILURES}"
    fi
done

TOTAL=$(( PASSED + FAILED ))

printf "Summary for tests:\n"
printf "================\n"
printf "  Passed: ${PASSED}\n"
printf "  Failed: ${FAILED}\n"
printf "  Total : ${TOTAL}\n"
printf "================\n"

if [ -n "${FAILURES}" ]; then
    printf "\nFailed tests:${FAILURES}\n"
fi
