
EXTERN createfile  : QWORD
EXTERN writefile   : QWORD
EXTERN closehandle : QWORD

.code
	FILE_APPEND_DATA        BYTE 4h
    FILE_SHARE_READ         BYTE 1h
    OPEN_ALWAYS             EQU 00000004h
    FILE_ATTRIBUTE_NORMAL   EQU 00000080h
    INVALID_HANDLE_VALUE    EQU 0FFFFFFFFh
; ---------------------------------------------------;
;   This procedure write data to file                ;                              
;   first param : byte to be written                 ;
;   second param: filepath                           ;
; ---------------------------------------------------;

writeTofile PROC
    push rbp                                        ; +8 B into the stack (don't forget 16 bit stack alignment)
    mov rbp,rsp                                     ; rbp is the frame pointer (it's not mandatory in 64 bit mode)      
    mov qword ptr[rbp+10h],rcx                      ; save argument in the first slote of the shadow space
    mov qword ptr[rbp+18h],rdx                      ; save the second argument into the second shadow space slot, filename
    sub rsp,80                                      ; space needed for calling a function with max 7 argument (56) + 1 local var (8) +allign(8)
    mov qword ptr[rbp-8], 0                         ; hfile variable
    ;-----------------------------------;
    ; create file                       ;
    ;-----------------------------------;
    mov qword ptr[rsp+30h], 0                       ; seventh argument (third of the stack)
    mov dword ptr[rsp+28h], FILE_ATTRIBUTE_NORMAL   ; sixth argument (second of the stack)
    mov dword ptr[rsp+20h], OPEN_ALWAYS             ; fifth argument (first of the stack)
    xor r9,r9                                       ; fourth argument
    mov r8b, FILE_SHARE_READ                         ; third argument
    mov dl,FILE_APPEND_DATA                        ; second argument
    mov rcx,qword ptr[rbp+18h]                      ; first argument, filename                  
    call createfile                                 ; call api function
    cmp rax,INVALID_HANDLE_VALUE                    ; check if return value is equal 0xffffffffff       
    je fine                                         ; exit 
    ;-----------------------------------;
    ; write file                        ;
    ;-----------------------------------;
    mov qword ptr[rbp-8],rax                        ; save hfile 
    mov qword ptr[rsp+20h], 0                       ; lpOverlapped
    mov r9,0                                        ; lpNumberOfBytesWritten
    mov r8,1                                        ; nNumberOfBytesToWrite
    lea rdx, [rbp+10h]                              ; lpBuffer
    mov rcx,qword ptr[rbp-8]                        ; hFile
    call writefile                                  ; call api function
    ;-----------------------------------;
    ; close handle                      ;
    ;-----------------------------------;
    mov rcx,qword ptr[rbp-8]                        ; file to close
    call closehandle                                ; call api function         
    fine:
    leave
    ret
writeTofile ENDP

; ---------------------------------------------------;
; This procedure calculate the string lenght         ;
; first argument address of the string               ;
; ---------------------------------------------------;
strLen PROC
    push rbp
    mov rbp,rsp
    sub rsp,8
    xor r8,r8
    xor r9,r9
ciclo:
    mov r8b, byte ptr[rcx+r9]
    cmp r8b,0h
    je fine
    inc r9
    jmp ciclo
fine:
    mov rax,r9 
    leave
    ret

strLen ENDP

; ---------------------------------------------------;
; This procedure return the address of kernel32.dll  ;
; The code supposes that the library has been        ;
; loaded as third as often happend, but i'am going   ; 
; to code a more flexible version of this            ;
; ---------------------------------------------------;
FindK32Addr PROC
    push rbp                                         ; +8B into the stack (don't forget 16 bit stack alignment)
    mov rbp,rsp                                      ; rbp is the frame pointer (it's not mandatory in 64 bit mode)
    sub rsp,8                                        ; +8 to allign the stack to 16
    mov rdx, gs:[60h]                                ; Get a pointer to the PEB
    mov rdx, [rdx+18h]                               ; Get PEB->Ldr
    mov rdx, [rdx+20h]                               ; get entry InMemoryOrder module list
    mov rdx,[rdx]                                    ; get first module
    mov rdx,[rdx]                                    ; get second module
    mov rax,[rdx+30h-16]                             ; -16B because in each entry the are flink and blink address 8+8=16B
fine:
    leave
    ret
FindK32Addr ENDP

; ---------------------------------------------------;
; This procedure calculate the ror hash of a string. ;
; param1: string                                     ;
; param2: size of the string                         ;
; ---------------------------------------------------;
CalcHash PROC
    xor rsi,rsi
    push rbp                                        ; +8B into the stack (don't forget 16 bit stack alignment)
    mov rbp,rsp                                     ; rbp is the frame pointer (it's not mandatory in 64 bit mode)
    sub rsp,24                                      ; +24B (16 for local variable (2), +8 to allign the stack to 16, total 24+8=32)
    mov qword ptr[rbp+16],rcx                       ; save the first argument into first shadow space slot, string pointer (str)
    mov qword ptr[rbp+24],rdx                       ; save the second argument into the second space slot, string size
    mov qword ptr[rbp-8], 0                         ; var1: hash=0      
    mov qword ptr[rbp-16],0                         ; var2: i=0
ciclo:
    mov rsi, qword ptr[rbp-16]                      ; var2=rsi = i
    mov rdi,qword ptr[rbp+24]                       ; second argument, size
    cmp rsi,rdi                                     ; compare counter i with size
    je fine                                         ; if i < size repeat, if not exit   
    xor rcx,rcx                                     ; rcx = 0
    xor rax,rax                                     ; rax = 0
    mov rbx, qword ptr[rbp+16]                      ; rbx = string address
    mov cl, byte ptr[rbx+rsi]                       ; bl = string[i]
    mov rax, qword ptr[rbp-8]                       ; rax = hash
    ror eax, 13                                     ; rax = hash = ror(hash,13)
    add rax,rcx                                     ; hash += string[i]
    mov qword ptr[rbp-8],rax                        ; save hash into memory
    inc rsi                                         ; i++
    mov qword ptr[rbp-16], rsi                      ; save new i state
    jmp ciclo
fine:
    mov rax, qword ptr[rbp-8]
    leave
    ret
calchash ENDP
end

