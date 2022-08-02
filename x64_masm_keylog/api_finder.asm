
EXTERN strLen  : PROC
EXTERN CalcHash: PROC
.code
; ---------------------------------------------------;
; This procedure return the address of any function. ;
; from the adddress of the library                   ;
; first  param : address of the library              ;
; second param : the hash to resolve                 ;
; ---------------------------------------------------;

HashResolver PROC
    push rbp                                         ; +8B into the stack (don't forget 16 bit stack alignment)
    mov rbp,rsp                                      ; rbp is the frame pointer (it's not mandatory in 64 bit mode)
    sub rsp,64                                       ; +48B (+32 for local variable (5), stack already aligned to 16)
    mov qword ptr[rbp+10h],rcx                       ; save the first argument into  the first shadow space slot, address of the library
    mov qword ptr[rbp+18h],rdx                       ; save the second argument into the second shadow space slot, hash to resolve
    mov qword ptr[rbp-8], 0                          ; var1: number of functions
    mov qword ptr[rbp-16],0                          ; var2: addOfnames
    mov qword ptr[rbp-24],0                          ; var3: addOfnamesOrd
    mov qword ptr[rbp-32],0                          ; var4: addOfFunc
    mov qword ptr[rbp-40],0                          ; var5: i (index)
    xor rax,rax                                      ; rax = 0
    xor rbx,rbx                                      ; rbx = 0
    xor rcx,rcx                                      ; rcx = 0
    mov rbx,qword ptr[rbp+10h]                       ; rbx = k32 address
    ; parsing the library headers in order to find the export table structure
    mov eax, dword ptr [rbx+3ch]                     ; e_lfanew (offset to pe signature,32 bit value)
    add rax,rbx                                      ; absolute value of the ntheader address
    mov ecx, dword ptr[rax+88h]                      ; rva of the export table
    add rcx,rbx                                      ; absolute address of the export table
    xor rax,rax                                      ; rax = 0
    mov eax,dword ptr[rcx+14h]                       ; number of functions
    mov qword ptr[rbp-8],rax                         ; save to the stack
    xor rax,rax                                      ; rax = 0
    mov eax,dword ptr[rcx+1ch]                       ; rva of addOfFunc
    add rax,rbx                                      ; absolute address of add of function
    mov qword ptr[rbp-32], rax                       ; save to te stack
    xor rax,rax                                      ; rax = 0
    mov eax,dword ptr[rcx+20h]                       ; rva of addOfnames
    add rax,rbx                                      ; absolute address of addrOfnames
    mov qword ptr[rbp-16], rax                       ; save to te stack
    xor rax,rax                                      ; rax = 0
    mov eax,dword ptr[rcx+24h]                       ; rva of addOfnamesOrd
    add rax,rbx                                      ; absolute address of addOfnamesOrd
    mov qword ptr[rbp-24], rax                       ; save to te stack
ciclo:
    ; parsing the string of the names
    xor rax,rax                                     ; rax = 0
    xor rbx,rbx                                     ; rbx = 0
    xor rcx,rcx                                     ; rcx = 0
    xor rdx,rdx                                     ; rdx = 0
    xor rdi,rdi                                     ; rdi = 0
    xor rsi,rsi                                     ; rsi = 0
    mov rsi,4                                       ; rsi = 4
    mov rdi,qword ptr[rbp-40]                       ; rdi = i
    mov rdx,qword ptr[rbp-8]                        ; rdx = number of functions
    cmp rdi, rdx                                    ; compare i with number of function (size)
    je fine                                         ; if i < size ? compute, else exit
    mov rax,qword ptr[rbp-16]                       ; rax = addOfname
    mov ecx,dword ptr[rax+(rdi*4)]                  ; rax = *(DWORD32*)(addOfname + (i *4));
    add rcx,qword ptr[rbp+10h]                      ; make the rva address become absolute by adding k32addres
    call strLen                                     ; address is already in rcx, now i'll calculate the string lenght
    mov rdx,rax                                     ; the size of the string as the second argument, the rcx already set-up
    call CalcHash                                   ; calulate the hash
    cmp rax,qword ptr[rbp+18h]                      ; compare just the two hash
    je hash_match                                   ; hash found
    xor rdi,rdi                                     ; rdi=0
    mov rdi,qword ptr[rbp-40]                       ; rdi=i
    inc rdi                                         ; i++
    mov qword ptr[rbp-40],rdi                       ; save 
    jmp ciclo                                       ; looping
hash_match:
    ; now i'ill get tha ordinal value from addOfnamesOrd
    xor rax,rax                                     ; rax = 0
    xor rbx,rbx                                     ; rbx = 0
    xor rcx,rcx                                     ; rcx = 0
    xor r9,r9                                       ; r9  = 0
    mov rax, qword ptr[rbp-40]                      ; rax = i
    mov rbx, qword ptr[rbp-24]                      ; rbx = addOfnamesOrd
    mov cx,word ptr[rbx+(rax*2)]                    ; get ordinal value *(ULONG*)(addOfnamesOrd+i*2)
    ; by using the ordinal value i'll get the address of the function
    mov rbx,qword ptr[rbp-32]                       ; rbx = addOfFunc
    mov eax, dword ptr[rbx + rcx*4]                 ;*(DWORD32*)addOfFunc+(ordinalValue*4)
    add rax,qword ptr[rbp+10h]                      ; absolute value of the function
fine:
    leave
    ret

HashResolver ENDP

end

