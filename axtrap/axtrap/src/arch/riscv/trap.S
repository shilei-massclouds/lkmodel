.section .text
.balign 4
.global trap_vector_base
trap_vector_base:
    // sscratch == 0: trap from S mode
    // sscratch != 0: trap from U mode
    csrrw   sp, sscratch, sp            // switch sscratch and sp
    bnez    sp, .Ltrap_entry_u

    csrr    sp, sscratch                // put supervisor sp back
    j       .Ltrap_entry_s

.Ltrap_entry_s:
    addi    sp, sp, -{trapframe_size}
    SAVE_REGS 0
    mv      a0, sp
    li      a1, 0
    call    riscv_trap_handler
    RESTORE_REGS 0
    sret

.Ltrap_entry_u:
    addi    sp, sp, -{trapframe_size}
    SAVE_REGS 1
    mv      a0, sp
    li      a1, 1
    call    riscv_trap_handler
    addi    t0, sp, {trapframe_size}    // put supervisor sp to scratch
    csrw    sscratch, t0
    RESTORE_REGS 1
    sret

.section .text
.balign 4
.global start_app
start_app:
    addi    sp, sp, -{trapframe_size}

    li      t2, 0x8000000200006100
    STR     t2, sp, 32                  // tf.sstatus
    STR     t0, sp, 31                  // tf.sepc
    STR     t1, sp, 1                   // tf.regs.sp(app stack)
    RESTORE_REGS 1
    mv      a0, zero
    sret