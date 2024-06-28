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
    auipc   a1, 0          # Load the upper 20 bits of the PC into a1
    addi    a1, a1, 12
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
