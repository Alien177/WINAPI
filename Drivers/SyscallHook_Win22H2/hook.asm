extern halCounterQueryRoutine:QWORD
extern keQueryPerformanceCounterHook:PROC

.code
temper PROC
    push rcx ;write a value stored in rcx on the stack
    mov rcx,rsp ;write a current stack pointer into rcx
    call keQueryPerformanceCounterHook
    pop rcx ;restore whatever is on the stack into the register
    mov rax, halCounterQueryRoutine 
    jmp rax
temper ENDP

end