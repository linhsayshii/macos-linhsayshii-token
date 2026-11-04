
.local/oneca-windows/extracted/sys/one-ca_v3.dll@64bit:	file format coff-x86-64

Disassembly of section .text:

0000000180004990 <C_SetPIN>:
180012310: 40 57                       	pushq	%rdi
180012312: 41 54                       	pushq	%r12
180012314: 41 55                       	pushq	%r13
180012316: 48 83 ec 40                 	subq	$0x40, %rsp
18001231a: 48 c7 44 24 30 fe ff ff ff  	movq	$-0x2, 0x30(%rsp)
180012323: 48 89 5c 24 60              	movq	%rbx, 0x60(%rsp)
180012328: 48 89 6c 24 70              	movq	%rbp, 0x70(%rsp)
18001232d: 48 89 74 24 78              	movq	%rsi, 0x78(%rsp)
180012332: 49 8b e9                    	movq	%r9, %rbp
180012335: 49 8b f8                    	movq	%r8, %rdi
180012338: 48 8b f2                    	movq	%rdx, %rsi
18001233b: 4c 8b e9                    	movq	%rcx, %r13
18001233e: 33 db                       	xorl	%ebx, %ebx
180012340: 8b 02                       	movl	(%rdx), %eax
180012342: 3d 36 01 00 00              	cmpl	$0x136, %eax            # imm = 0x136
180012347: 0f 87 b3 04 00 00           	ja	0x180012800 <C_SetPIN+0xde70>
18001234d: 3d 36 01 00 00              	cmpl	$0x136, %eax            # imm = 0x136
180012352: 0f 84 42 05 00 00           	je	0x18001289a <C_SetPIN+0xdf0a>
180012358: 83 f8 42                    	cmpl	$0x42, %eax
18001235b: 0f 87 9a 02 00 00           	ja	0x1800125fb <C_SetPIN+0xdc6b>
180012361: 83 f8 40                    	cmpl	$0x40, %eax
180012364: 0f 83 55 02 00 00           	jae	0x1800125bf <C_SetPIN+0xdc2f>
18001236a: 83 f8 0c                    	cmpl	$0xc, %eax
18001236d: 0f 87 6e 05 00 00           	ja	0x1800128e1 <C_SetPIN+0xdf51>
180012373: 48 8d 15 86 dc fe ff        	leaq	-0x1237a(%rip), %rdx    # 0x180000000
18001237a: 8b 84 82 dc 29 01 00        	movl	0x129dc(%rdx,%rax,4), %eax
180012381: 48 03 c2                    	addq	%rdx, %rax
180012384: ff e0                       	jmpq	*%rax
180012386: 49 8b c8                    	movq	%r8, %rcx
180012389: e8 92 5e ff ff              	callq	0x180008220 <C_SetPIN+0x3890>
18001238e: 84 c0                       	testb	%al, %al
180012390: 0f 84 29 06 00 00           	je	0x1800129bf <C_SetPIN+0xe02f>
180012396: b9 88 00 00 00              	movl	$0x88, %ecx
18001239b: e8 b4 c0 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
1800123a0: 4c 8b d8                    	movq	%rax, %r11
1800123a3: 48 85 c0                    	testq	%rax, %rax
1800123a6: 0f 84 03 06 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
1800123ac: 48 8d 05 c5 0b 08 00        	leaq	0x80bc5(%rip), %rax     # 0x180092f78
1800123b3: 49 89 03                    	movq	%rax, (%r11)
1800123b6: 48 8d 05 4b ee 07 00        	leaq	0x7ee4b(%rip), %rax     # 0x180091208
1800123bd: 49 89 43 10                 	movq	%rax, 0x10(%r11)
1800123c1: 41 89 5b 30                 	movl	%ebx, 0x30(%r11)
1800123c5: 49 89 5b 28                 	movq	%rbx, 0x28(%r11)
1800123c9: 8b 06                       	movl	(%rsi), %eax
1800123cb: 41 89 43 18                 	movl	%eax, 0x18(%r11)
1800123cf: 48 8b 46 04                 	movq	0x4(%rsi), %rax
1800123d3: 49 89 43 28                 	movq	%rax, 0x28(%r11)
1800123d7: 8b 46 0c                    	movl	0xc(%rsi), %eax
1800123da: 41 89 43 30                 	movl	%eax, 0x30(%r11)
1800123de: 48 8d 05 73 08 08 00        	leaq	0x80873(%rip), %rax     # 0x180092c58
1800123e5: 49 89 03                    	movq	%rax, (%r11)
1800123e8: 49 89 5b 40                 	movq	%rbx, 0x40(%r11)
1800123ec: 49 89 5b 50                 	movq	%rbx, 0x50(%r11)
1800123f0: 49 89 5b 48                 	movq	%rbx, 0x48(%r11)
1800123f4: 41 89 5b 58                 	movl	%ebx, 0x58(%r11)
1800123f8: 48 8d 05 79 0c 08 00        	leaq	0x80c79(%rip), %rax     # 0x180093078
1800123ff: 49 89 43 70                 	movq	%rax, 0x70(%r11)
180012403: 49 89 7b 60                 	movq	%rdi, 0x60(%r11)
180012407: 49 89 6b 68                 	movq	%rbp, 0x68(%r11)
18001240b: 41 c7 83 80 00 00 00 80 00 00 00    	movl	$0x80, 0x80(%r11)
180012416: 49 89 6b 78                 	movq	%rbp, 0x78(%r11)
18001241a: 49 8b db                    	movq	%r11, %rbx
18001241d: e9 8d 05 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
180012422: b9 80 00 00 00              	movl	$0x80, %ecx
180012427: e8 28 c0 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
18001242c: 4c 8b d8                    	movq	%rax, %r11
18001242f: 48 85 c0                    	testq	%rax, %rax
180012432: 0f 84 77 05 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
180012438: 48 8d 05 39 0b 08 00        	leaq	0x80b39(%rip), %rax     # 0x180092f78
18001243f: 49 89 03                    	movq	%rax, (%r11)
180012442: 48 8d 05 bf ed 07 00        	leaq	0x7edbf(%rip), %rax     # 0x180091208
180012449: 49 89 43 10                 	movq	%rax, 0x10(%r11)
18001244d: 41 89 5b 30                 	movl	%ebx, 0x30(%r11)
180012451: 49 89 5b 28                 	movq	%rbx, 0x28(%r11)
180012455: 8b 06                       	movl	(%rsi), %eax
180012457: 41 89 43 18                 	movl	%eax, 0x18(%r11)
18001245b: 48 8b 46 04                 	movq	0x4(%rsi), %rax
18001245f: 49 89 43 28                 	movq	%rax, 0x28(%r11)
180012463: 8b 46 0c                    	movl	0xc(%rsi), %eax
180012466: 41 89 43 30                 	movl	%eax, 0x30(%r11)
18001246a: 48 8d 05 e7 09 08 00        	leaq	0x809e7(%rip), %rax     # 0x180092e58
180012471: 49 89 03                    	movq	%rax, (%r11)
180012474: 49 89 5b 40                 	movq	%rbx, 0x40(%r11)
180012478: 49 89 5b 50                 	movq	%rbx, 0x50(%r11)
18001247c: 49 89 5b 48                 	movq	%rbx, 0x48(%r11)
180012480: 41 89 5b 58                 	movl	%ebx, 0x58(%r11)
180012484: 48 8d 05 ed 0b 08 00        	leaq	0x80bed(%rip), %rax     # 0x180093078
18001248b: 49 89 43 70                 	movq	%rax, 0x70(%r11)
18001248f: 49 89 7b 60                 	movq	%rdi, 0x60(%r11)
180012493: 49 89 6b 68                 	movq	%rbp, 0x68(%r11)
180012497: 49 89 6b 78                 	movq	%rbp, 0x78(%r11)
18001249b: 49 8b db                    	movq	%r11, %rbx
18001249e: e9 0c 05 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
1800124a3: 49 8b c8                    	movq	%r8, %rcx
1800124a6: e8 75 5d ff ff              	callq	0x180008220 <C_SetPIN+0x3890>
1800124ab: 84 c0                       	testb	%al, %al
1800124ad: 0f 84 0c 05 00 00           	je	0x1800129bf <C_SetPIN+0xe02f>
1800124b3: b9 60 01 00 00              	movl	$0x160, %ecx            # imm = 0x160
1800124b8: e8 97 bf 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
1800124bd: 4c 8b d8                    	movq	%rax, %r11
1800124c0: 48 85 c0                    	testq	%rax, %rax
1800124c3: 0f 84 e6 04 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
1800124c9: 48 8d 05 a8 0a 08 00        	leaq	0x80aa8(%rip), %rax     # 0x180092f78
1800124d0: 49 89 03                    	movq	%rax, (%r11)
1800124d3: 48 8d 05 2e ed 07 00        	leaq	0x7ed2e(%rip), %rax     # 0x180091208
1800124da: 49 89 43 10                 	movq	%rax, 0x10(%r11)
1800124de: 41 89 5b 30                 	movl	%ebx, 0x30(%r11)
1800124e2: 49 89 5b 28                 	movq	%rbx, 0x28(%r11)
1800124e6: 8b 06                       	movl	(%rsi), %eax
1800124e8: 41 89 43 18                 	movl	%eax, 0x18(%r11)
1800124ec: 48 8b 46 04                 	movq	0x4(%rsi), %rax
1800124f0: 49 89 43 28                 	movq	%rax, 0x28(%r11)
1800124f4: 8b 46 0c                    	movl	0xc(%rsi), %eax
1800124f7: 41 89 43 30                 	movl	%eax, 0x30(%r11)
1800124fb: 48 8d 05 36 fc 07 00        	leaq	0x7fc36(%rip), %rax     # 0x180092138
180012502: 49 89 03                    	movq	%rax, (%r11)
180012505: 49 89 9b 18 01 00 00        	movq	%rbx, 0x118(%r11)
18001250c: 49 89 9b 28 01 00 00        	movq	%rbx, 0x128(%r11)
180012513: 49 89 9b 20 01 00 00        	movq	%rbx, 0x120(%r11)
18001251a: 41 89 9b 30 01 00 00        	movl	%ebx, 0x130(%r11)
180012521: 48 8d 05 50 0b 08 00        	leaq	0x80b50(%rip), %rax     # 0x180093078
180012528: 49 89 83 48 01 00 00        	movq	%rax, 0x148(%r11)
18001252f: 49 89 bb 38 01 00 00        	movq	%rdi, 0x138(%r11)
180012536: 49 89 ab 40 01 00 00        	movq	%rbp, 0x140(%r11)
18001253d: 41 c7 83 58 01 00 00 81 00 00 00    	movl	$0x81, 0x158(%r11)
180012548: 49 89 ab 50 01 00 00        	movq	%rbp, 0x150(%r11)
18001254f: 49 8b db                    	movq	%r11, %rbx
180012552: e9 58 04 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
180012557: 49 8b c8                    	movq	%r8, %rcx
18001255a: e8 c1 5c ff ff              	callq	0x180008220 <C_SetPIN+0x3890>
18001255f: 84 c0                       	testb	%al, %al
180012561: 0f 84 58 04 00 00           	je	0x1800129bf <C_SetPIN+0xe02f>
180012567: b9 b0 00 00 00              	movl	$0xb0, %ecx
18001256c: e8 e3 be 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
180012571: 48 85 c0                    	testq	%rax, %rax
180012574: 0f 84 35 04 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
18001257a: 4c 8b cd                    	movq	%rbp, %r9
18001257d: 4c 8b c7                    	movq	%rdi, %r8
180012580: 48 8b d6                    	movq	%rsi, %rdx
180012583: 48 8b c8                    	movq	%rax, %rcx
180012586: e8 b5 ac 00 00              	callq	0x18001d240 <C_SetPIN+0x188b0>
18001258b: 48 8b d8                    	movq	%rax, %rbx
18001258e: e9 1c 04 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
180012593: b9 08 06 00 00              	movl	$0x608, %ecx            # imm = 0x608
180012598: e8 b7 be 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
18001259d: 48 85 c0                    	testq	%rax, %rax
1800125a0: 0f 84 09 04 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
1800125a6: 4c 8b cd                    	movq	%rbp, %r9
1800125a9: 4c 8b c7                    	movq	%rdi, %r8
1800125ac: 48 8b d6                    	movq	%rsi, %rdx
1800125af: 48 8b c8                    	movq	%rax, %rcx
1800125b2: e8 09 82 00 00              	callq	0x18001a7c0 <C_SetPIN+0x15e30>
1800125b7: 48 8b d8                    	movq	%rax, %rbx
1800125ba: e9 f0 03 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
1800125bf: 49 8b c8                    	movq	%r8, %rcx
1800125c2: e8 59 5c ff ff              	callq	0x180008220 <C_SetPIN+0x3890>
1800125c7: 84 c0                       	testb	%al, %al
1800125c9: 0f 84 f0 03 00 00           	je	0x1800129bf <C_SetPIN+0xe02f>
1800125cf: b9 08 06 00 00              	movl	$0x608, %ecx            # imm = 0x608
1800125d4: e8 7b be 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
1800125d9: 48 85 c0                    	testq	%rax, %rax
1800125dc: 0f 84 cd 03 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
1800125e2: 4c 8b cd                    	movq	%rbp, %r9
1800125e5: 4c 8b c7                    	movq	%rdi, %r8
1800125e8: 48 8b d6                    	movq	%rsi, %rdx
1800125eb: 48 8b c8                    	movq	%rax, %rcx
1800125ee: e8 6d b1 00 00              	callq	0x18001d760 <C_SetPIN+0x18dd0>
1800125f3: 48 8b d8                    	movq	%rax, %rbx
1800125f6: e9 b4 03 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
1800125fb: 05 00 ff ff ff              	addl	$0xffffff00, %eax       # imm = 0xFFFFFF00
180012600: 83 f8 33                    	cmpl	$0x33, %eax
180012603: 0f 87 d8 02 00 00           	ja	0x1800128e1 <C_SetPIN+0xdf51>
180012609: 48 8d 15 f0 d9 fe ff        	leaq	-0x12610(%rip), %rdx    # 0x180000000
180012610: 0f b6 84 02 24 2a 01 00     	movzbl	0x12a24(%rdx,%rax), %eax
180012618: 8b 8c 82 10 2a 01 00        	movl	0x12a10(%rdx,%rax,4), %ecx
18001261f: 48 03 ca                    	addq	%rdx, %rcx
180012622: ff e1                       	jmpq	*%rcx
180012624: b9 b0 03 00 00              	movl	$0x3b0, %ecx            # imm = 0x3B0
180012629: e8 26 be 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
18001262e: 4c 8b e0                    	movq	%rax, %r12
180012631: 48 85 c0                    	testq	%rax, %rax
180012634: 0f 84 75 03 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
18001263a: 48 8d 05 37 09 08 00        	leaq	0x80937(%rip), %rax     # 0x180092f78
180012641: 49 89 04 24                 	movq	%rax, (%r12)
180012645: 48 8d 05 bc eb 07 00        	leaq	0x7ebbc(%rip), %rax     # 0x180091208
18001264c: 49 89 44 24 10              	movq	%rax, 0x10(%r12)
180012651: 41 89 5c 24 30              	movl	%ebx, 0x30(%r12)
180012656: 49 89 5c 24 28              	movq	%rbx, 0x28(%r12)
18001265b: 8b 06                       	movl	(%rsi), %eax
18001265d: 41 89 44 24 18              	movl	%eax, 0x18(%r12)
180012662: 48 8b 46 04                 	movq	0x4(%rsi), %rax
180012666: 49 89 44 24 28              	movq	%rax, 0x28(%r12)
18001266b: 8b 46 0c                    	movl	0xc(%rsi), %eax
18001266e: 41 89 44 24 30              	movl	%eax, 0x30(%r12)
180012673: 48 8d 05 de 06 08 00        	leaq	0x806de(%rip), %rax     # 0x180092d58
18001267a: 49 89 04 24                 	movq	%rax, (%r12)
18001267e: 49 89 5c 24 50              	movq	%rbx, 0x50(%r12)
180012683: 49 89 5c 24 60              	movq	%rbx, 0x60(%r12)
180012688: 49 89 5c 24 58              	movq	%rbx, 0x58(%r12)
18001268d: 41 89 5c 24 68              	movl	%ebx, 0x68(%r12)
180012692: 49 89 7c 24 40              	movq	%rdi, 0x40(%r12)
180012697: 49 8d 4c 24 70              	leaq	0x70(%r12), %rcx
18001269c: 33 d2                       	xorl	%edx, %edx
18001269e: 41 b8 00 03 00 00           	movl	$0x300, %r8d            # imm = 0x300
1800126a4: e8 c7 ed 01 00              	callq	0x180031470 <C_SetPIN+0x2cae0>
1800126a9: 49 89 6c 24 48              	movq	%rbp, 0x48(%r12)
1800126ae: 49 8b dc                    	movq	%r12, %rbx
1800126b1: e9 f9 02 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
1800126b6: 49 8b c8                    	movq	%r8, %rcx
1800126b9: e8 62 5b ff ff              	callq	0x180008220 <C_SetPIN+0x3890>
1800126be: 84 c0                       	testb	%al, %al
1800126c0: 74 07                       	je	0x1800126c9 <C_SetPIN+0xdd39>
1800126c2: 33 c0                       	xorl	%eax, %eax
1800126c4: e9 f9 02 00 00              	jmp	0x1800129c2 <C_SetPIN+0xe032>
1800126c9: b9 b0 01 00 00              	movl	$0x1b0, %ecx            # imm = 0x1B0
1800126ce: e8 81 bd 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
1800126d3: 4c 8b e0                    	movq	%rax, %r12
1800126d6: 48 85 c0                    	testq	%rax, %rax
1800126d9: 0f 84 d0 02 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
1800126df: 48 8d 05 92 08 08 00        	leaq	0x80892(%rip), %rax     # 0x180092f78
1800126e6: 49 89 04 24                 	movq	%rax, (%r12)
1800126ea: 48 8d 05 17 eb 07 00        	leaq	0x7eb17(%rip), %rax     # 0x180091208
1800126f1: 49 89 44 24 10              	movq	%rax, 0x10(%r12)
1800126f6: 41 89 5c 24 30              	movl	%ebx, 0x30(%r12)
1800126fb: 49 89 5c 24 28              	movq	%rbx, 0x28(%r12)
180012700: 8b 06                       	movl	(%rsi), %eax
180012702: 41 89 44 24 18              	movl	%eax, 0x18(%r12)
180012707: 48 8b 46 04                 	movq	0x4(%rsi), %rax
18001270b: 49 89 44 24 28              	movq	%rax, 0x28(%r12)
180012710: 8b 46 0c                    	movl	0xc(%rsi), %eax
180012713: 41 89 44 24 30              	movl	%eax, 0x30(%r12)
180012718: 48 8d 05 39 02 08 00        	leaq	0x80239(%rip), %rax     # 0x180092958
18001271f: 49 89 04 24                 	movq	%rax, (%r12)
180012723: 49 89 5c 24 50              	movq	%rbx, 0x50(%r12)
180012728: 49 89 5c 24 60              	movq	%rbx, 0x60(%r12)
18001272d: 49 89 5c 24 58              	movq	%rbx, 0x58(%r12)
180012732: 41 89 5c 24 68              	movl	%ebx, 0x68(%r12)
180012737: 49 89 7c 24 40              	movq	%rdi, 0x40(%r12)
18001273c: 49 8d 4c 24 70              	leaq	0x70(%r12), %rcx
180012741: 33 d2                       	xorl	%edx, %edx
180012743: 41 b8 00 01 00 00           	movl	$0x100, %r8d            # imm = 0x100
180012749: e8 22 ed 01 00              	callq	0x180031470 <C_SetPIN+0x2cae0>
18001274e: 49 89 6c 24 48              	movq	%rbp, 0x48(%r12)
180012753: 49 8b dc                    	movq	%r12, %rbx
180012756: e9 54 02 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
18001275b: 49 8b c8                    	movq	%r8, %rcx
18001275e: e8 bd 5a ff ff              	callq	0x180008220 <C_SetPIN+0x3890>
180012763: 84 c0                       	testb	%al, %al
180012765: 74 07                       	je	0x18001276e <C_SetPIN+0xddde>
180012767: 33 c0                       	xorl	%eax, %eax
180012769: e9 54 02 00 00              	jmp	0x1800129c2 <C_SetPIN+0xe032>
18001276e: b9 78 04 00 00              	movl	$0x478, %ecx            # imm = 0x478
180012773: e8 dc bc 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
180012778: 4c 8b e0                    	movq	%rax, %r12
18001277b: 48 85 c0                    	testq	%rax, %rax
18001277e: 0f 84 2b 02 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
180012784: 48 8d 05 ed 07 08 00        	leaq	0x807ed(%rip), %rax     # 0x180092f78
18001278b: 49 89 04 24                 	movq	%rax, (%r12)
18001278f: 48 8d 05 72 ea 07 00        	leaq	0x7ea72(%rip), %rax     # 0x180091208
180012796: 49 89 44 24 10              	movq	%rax, 0x10(%r12)
18001279b: 41 89 5c 24 30              	movl	%ebx, 0x30(%r12)
1800127a0: 49 89 5c 24 28              	movq	%rbx, 0x28(%r12)
1800127a5: 8b 06                       	movl	(%rsi), %eax
1800127a7: 41 89 44 24 18              	movl	%eax, 0x18(%r12)
1800127ac: 48 8b 46 04                 	movq	0x4(%rsi), %rax
1800127b0: 49 89 44 24 28              	movq	%rax, 0x28(%r12)
1800127b5: 8b 46 0c                    	movl	0xc(%rsi), %eax
1800127b8: 41 89 44 24 30              	movl	%eax, 0x30(%r12)
1800127bd: 48 8d 05 94 02 08 00        	leaq	0x80294(%rip), %rax     # 0x180092a58
1800127c4: 49 89 04 24                 	movq	%rax, (%r12)
1800127c8: 49 89 5c 24 48              	movq	%rbx, 0x48(%r12)
1800127cd: 49 89 5c 24 58              	movq	%rbx, 0x58(%r12)
1800127d2: 49 89 5c 24 50              	movq	%rbx, 0x50(%r12)
1800127d7: 41 89 5c 24 60              	movl	%ebx, 0x60(%r12)
1800127dc: 49 89 7c 24 40              	movq	%rdi, 0x40(%r12)
1800127e1: 49 89 6c 24 68              	movq	%rbp, 0x68(%r12)
1800127e6: 49 8d 4c 24 70              	leaq	0x70(%r12), %rcx
1800127eb: 33 d2                       	xorl	%edx, %edx
1800127ed: 41 b8 08 04 00 00           	movl	$0x408, %r8d            # imm = 0x408
1800127f3: e8 78 ec 01 00              	callq	0x180031470 <C_SetPIN+0x2cae0>
1800127f8: 49 8b dc                    	movq	%r12, %rbx
1800127fb: e9 af 01 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
180012800: 3d 93 03 00 00              	cmpl	$0x393, %eax            # imm = 0x393
180012805: 77 3e                       	ja	0x180012845 <C_SetPIN+0xdeb5>
180012807: 3d 92 03 00 00              	cmpl	$0x392, %eax            # imm = 0x392
18001280c: 73 60                       	jae	0x18001286e <C_SetPIN+0xdede>
18001280e: 3d 60 02 00 00              	cmpl	$0x260, %eax            # imm = 0x260
180012813: 77 1d                       	ja	0x180012832 <C_SetPIN+0xdea2>
180012815: 3d 60 02 00 00              	cmpl	$0x260, %eax            # imm = 0x260
18001281a: 74 52                       	je	0x18001286e <C_SetPIN+0xdede>
18001281c: 2d 10 02 00 00              	subl	$0x210, %eax            # imm = 0x210
180012821: 74 4b                       	je	0x18001286e <C_SetPIN+0xdede>
180012823: 83 e8 10                    	subl	$0x10, %eax
180012826: 74 46                       	je	0x18001286e <C_SetPIN+0xdede>
180012828: 83 f8 30                    	cmpl	$0x30, %eax
18001282b: 74 41                       	je	0x18001286e <C_SetPIN+0xdede>
18001282d: e9 af 00 00 00              	jmp	0x1800128e1 <C_SetPIN+0xdf51>
180012832: 3d 70 02 00 00              	cmpl	$0x270, %eax            # imm = 0x270
180012837: 74 35                       	je	0x18001286e <C_SetPIN+0xdede>
180012839: 3d 90 03 00 00              	cmpl	$0x390, %eax            # imm = 0x390
18001283e: 74 2e                       	je	0x18001286e <C_SetPIN+0xdede>
180012840: e9 9c 00 00 00              	jmp	0x1800128e1 <C_SetPIN+0xdf51>
180012845: 3d 85 10 00 00              	cmpl	$0x1085, %eax           # imm = 0x1085
18001284a: 0f 87 83 00 00 00           	ja	0x1800128d3 <C_SetPIN+0xdf43>
180012850: 3d 85 10 00 00              	cmpl	$0x1085, %eax           # imm = 0x1085
180012855: 74 43                       	je	0x18001289a <C_SetPIN+0xdf0a>
180012857: 3d 95 03 00 00              	cmpl	$0x395, %eax            # imm = 0x395
18001285c: 74 10                       	je	0x18001286e <C_SetPIN+0xdede>
18001285e: 3d 7f 10 00 00              	cmpl	$0x107f, %eax           # imm = 0x107F
180012863: 76 7c                       	jbe	0x1800128e1 <C_SetPIN+0xdf51>
180012865: 3d 82 10 00 00              	cmpl	$0x1082, %eax           # imm = 0x1082
18001286a: 76 2e                       	jbe	0x18001289a <C_SetPIN+0xdf0a>
18001286c: eb 73                       	jmp	0x1800128e1 <C_SetPIN+0xdf51>
18001286e: b9 90 00 00 00              	movl	$0x90, %ecx
180012873: e8 dc bb 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
180012878: 48 85 c0                    	testq	%rax, %rax
18001287b: 0f 84 2e 01 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
180012881: 4c 8b cd                    	movq	%rbp, %r9
180012884: 4c 8b c7                    	movq	%rdi, %r8
180012887: 48 8b d6                    	movq	%rsi, %rdx
18001288a: 48 8b c8                    	movq	%rax, %rcx
18001288d: e8 5e cc 00 00              	callq	0x18001f4f0 <C_SetPIN+0x1ab60>
180012892: 48 8b d8                    	movq	%rax, %rbx
180012895: e9 15 01 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
18001289a: b9 d0 04 00 00              	movl	$0x4d0, %ecx            # imm = 0x4D0
18001289f: e8 b0 bb 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
1800128a4: 48 89 44 24 68              	movq	%rax, 0x68(%rsp)
1800128a9: 48 85 c0                    	testq	%rax, %rax
1800128ac: 74 20                       	je	0x1800128ce <C_SetPIN+0xdf3e>
1800128ae: 0f b6 8c 24 80 00 00 00     	movzbl	0x80(%rsp), %ecx
1800128b6: 88 4c 24 20                 	movb	%cl, 0x20(%rsp)
1800128ba: 4c 8b cd                    	movq	%rbp, %r9
1800128bd: 4c 8b c7                    	movq	%rdi, %r8
1800128c0: 48 8b d6                    	movq	%rsi, %rdx
1800128c3: 48 8b c8                    	movq	%rax, %rcx
1800128c6: e8 e5 89 00 00              	callq	0x18001b2b0 <C_SetPIN+0x16920>
1800128cb: 48 8b d8                    	movq	%rax, %rbx
1800128ce: e9 dc 00 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
1800128d3: 3d 00 00 00 83              	cmpl	$0x83000000, %eax       # imm = 0x83000000
1800128d8: 74 52                       	je	0x18001292c <C_SetPIN+0xdf9c>
1800128da: 3d 01 00 00 83              	cmpl	$0x83000001, %eax       # imm = 0x83000001
1800128df: 74 1f                       	je	0x180012900 <C_SetPIN+0xdf70>
1800128e1: 0f b6 84 24 80 00 00 00     	movzbl	0x80(%rsp), %eax
1800128e9: 88 44 24 20                 	movb	%al, 0x20(%rsp)
1800128ed: 48 8b d6                    	movq	%rsi, %rdx
1800128f0: 49 8b cd                    	movq	%r13, %rcx
1800128f3: e8 c8 01 00 00              	callq	0x180012ac0 <C_SetPIN+0xe130>
1800128f8: 48 8b d8                    	movq	%rax, %rbx
1800128fb: e9 af 00 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
180012900: b9 70 01 00 00              	movl	$0x170, %ecx            # imm = 0x170
180012905: e8 4a bb 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
18001290a: 48 85 c0                    	testq	%rax, %rax
18001290d: 0f 84 9c 00 00 00           	je	0x1800129af <C_SetPIN+0xe01f>
180012913: 4c 8b cd                    	movq	%rbp, %r9
180012916: 4c 8b c7                    	movq	%rdi, %r8
180012919: 48 8b d6                    	movq	%rsi, %rdx
18001291c: 48 8b c8                    	movq	%rax, %rcx
18001291f: e8 ac 99 00 00              	callq	0x18001c2d0 <C_SetPIN+0x17940>
180012924: 48 8b d8                    	movq	%rax, %rbx
180012927: e9 83 00 00 00              	jmp	0x1800129af <C_SetPIN+0xe01f>
18001292c: b9 88 00 00 00              	movl	$0x88, %ecx
180012931: e8 1e bb 01 00              	callq	0x18002e454 <C_SetPIN+0x29ac4>
180012936: 4c 8b d8                    	movq	%rax, %r11
180012939: 48 85 c0                    	testq	%rax, %rax
18001293c: 74 71                       	je	0x1800129af <C_SetPIN+0xe01f>
18001293e: 48 8d 05 33 06 08 00        	leaq	0x80633(%rip), %rax     # 0x180092f78
180012945: 49 89 03                    	movq	%rax, (%r11)
180012948: 48 8d 05 b9 e8 07 00        	leaq	0x7e8b9(%rip), %rax     # 0x180091208
18001294f: 49 89 43 10                 	movq	%rax, 0x10(%r11)
180012953: 41 89 5b 30                 	movl	%ebx, 0x30(%r11)
180012957: 49 89 5b 28                 	movq	%rbx, 0x28(%r11)
18001295b: 8b 06                       	movl	(%rsi), %eax
18001295d: 41 89 43 18                 	movl	%eax, 0x18(%r11)
180012961: 48 8b 46 04                 	movq	0x4(%rsi), %rax
180012965: 49 89 43 28                 	movq	%rax, 0x28(%r11)
180012969: 8b 46 0c                    	movl	0xc(%rsi), %eax
18001296c: 41 89 43 30                 	movl	%eax, 0x30(%r11)
180012970: 48 8d 05 e1 fb 07 00        	leaq	0x7fbe1(%rip), %rax     # 0x180092558
180012977: 49 89 03                    	movq	%rax, (%r11)
18001297a: 49 89 5b 40                 	movq	%rbx, 0x40(%r11)
18001297e: 49 89 5b 50                 	movq	%rbx, 0x50(%r11)
180012982: 49 89 5b 48                 	movq	%rbx, 0x48(%r11)
180012986: 41 89 5b 58                 	movl	%ebx, 0x58(%r11)
18001298a: 48 8d 05 17 07 08 00        	leaq	0x80717(%rip), %rax     # 0x1800930a8
180012991: 49 89 43 70                 	movq	%rax, 0x70(%r11)
180012995: 49 89 7b 60                 	movq	%rdi, 0x60(%r11)
180012999: 49 89 6b 68                 	movq	%rbp, 0x68(%r11)
18001299d: 41 c7 83 80 00 00 00 80 00 00 00    	movl	$0x80, 0x80(%r11)
1800129a8: 49 89 6b 78                 	movq	%rbp, 0x78(%r11)
1800129ac: 49 8b db                    	movq	%r11, %rbx
1800129af: 48 85 db                    	testq	%rbx, %rbx
1800129b2: 74 0b                       	je	0x1800129bf <C_SetPIN+0xe02f>
1800129b4: 48 8b d3                    	movq	%rbx, %rdx
1800129b7: 49 8b cd                    	movq	%r13, %rcx
1800129ba: e8 81 f1 ff ff              	callq	0x180011b40 <C_SetPIN+0xd1b0>
1800129bf: 48 8b c3                    	movq	%rbx, %rax
1800129c2: 48 8b 5c 24 60              	movq	0x60(%rsp), %rbx
1800129c7: 48 8b 6c 24 70              	movq	0x70(%rsp), %rbp
1800129cc: 48 8b 74 24 78              	movq	0x78(%rsp), %rsi
1800129d1: 48 83 c4 40                 	addq	$0x40, %rsp
1800129d5: 41 5d                       	popq	%r13
1800129d7: 41 5c                       	popq	%r12
1800129d9: 5f                          	popq	%rdi
1800129da: c3                          	retq
1800129db: 90                          	nop
1800129dc: 86 23                       	xchgb	%ah, (%rbx)
1800129de: 01 00                       	addl	%eax, (%rax)
1800129e0: 86 23                       	xchgb	%ah, (%rbx)
1800129e2: 01 00                       	addl	%eax, (%rax)
1800129e4: e1 28                       	loope	0x180012a0e <C_SetPIN+0xe07e>
1800129e6: 01 00                       	addl	%eax, (%rax)
1800129e8: 22 24 01                    	andb	(%rcx,%rax), %ah
1800129eb: 00 e1                       	addb	%ah, %cl
1800129ed: 28 01                       	subb	%al, (%rcx)
1800129ef: 00 a3 24 01 00 bf           	addb	%ah, -0x40fffedc(%rbx)
1800129f5: 25 01 00 e1 28              	andl	$0x28e10001, %eax       # imm = 0x28E10001
1800129fa: 01 00                       	addl	%eax, (%rax)
1800129fc: e1 28                       	loope	0x180012a26 <C_SetPIN+0xe096>
1800129fe: 01 00                       	addl	%eax, (%rax)
180012a00: e1 28                       	loope	0x180012a2a <C_SetPIN+0xe09a>
180012a02: 01 00                       	addl	%eax, (%rax)
180012a04: 57                          	pushq	%rdi
180012a05: 25 01 00 57 25              	andl	$0x25570001, %eax       # imm = 0x25570001
180012a0a: 01 00                       	addl	%eax, (%rax)
180012a0c: 93                          	xchgl	%ebx, %eax
180012a0d: 25 01 00 b6 26              	andl	$0x26b60001, %eax       # imm = 0x26B60001
180012a12: 01 00                       	addl	%eax, (%rax)
180012a14: 5b                          	popq	%rbx
180012a15: 27                          	<unknown>
180012a16: 01 00                       	addl	%eax, (%rax)
180012a18: 9a                          	<unknown>
180012a19: 28 01                       	subb	%al, (%rcx)
180012a1b: 00 24 26                    	addb	%ah, (%rsi,%riz)
180012a1e: 01 00                       	addl	%eax, (%rax)
180012a20: e1 28                       	loope	0x180012a4a <C_SetPIN+0xe0ba>
180012a22: 01 00                       	addl	%eax, (%rax)
180012a24: 00 00                       	addb	%al, (%rax)
180012a26: 00 04 04                    	addb	%al, (%rsp,%rax)
180012a29: 04 04                       	addb	$0x4, %al
180012a2b: 04 04                       	addb	$0x4, %al
180012a2d: 04 04                       	addb	$0x4, %al
180012a2f: 04 04                       	addb	$0x4, %al
180012a31: 04 04                       	addb	$0x4, %al
180012a33: 04 01                       	addb	$0x1, %al
180012a35: 01 04 04                    	addl	%eax, (%rsp,%rax)
180012a38: 04 04                       	addb	$0x4, %al
180012a3a: 04 04                       	addb	$0x4, %al
180012a3c: 04 04                       	addb	$0x4, %al
180012a3e: 04 04                       	addb	$0x4, %al
180012a40: 04 04                       	addb	$0x4, %al
180012a42: 04 04                       	addb	$0x4, %al
180012a44: 02 02                       	addb	(%rdx), %al
180012a46: 02 04 04                    	addb	(%rsp,%rax), %al
180012a49: 02 04 04                    	addb	(%rsp,%rax), %al
180012a4c: 04 04                       	addb	$0x4, %al
180012a4e: 04 04                       	addb	$0x4, %al
180012a50: 04 04                       	addb	$0x4, %al
180012a52: 04 04                       	addb	$0x4, %al
180012a54: 04 02                       	addb	$0x2, %al
180012a56: 03 03                       	addl	(%rbx), %eax
180012a58: cc                          	int3
180012a59: cc                          	int3
180012a5a: cc                          	int3
180012a5b: cc                          	int3
180012a5c: cc                          	int3
180012a5d: cc                          	int3
180012a5e: cc                          	int3
180012a5f: cc                          	int3
180012a60: 48 83 ec 28                 	subq	$0x28, %rsp
180012a64: 4c 8b 41 08                 	movq	0x8(%rcx), %r8
180012a68: 49 39 50 10                 	cmpq	%rdx, 0x10(%r8)
180012a6c: 75 1a                       	jne	0x180012a88 <C_SetPIN+0xe0f8>
180012a6e: 49 8b 40 08                 	movq	0x8(%r8), %rax
180012a72: ba 01 00 00 00              	movl	$0x1, %edx
180012a77: 48 89 41 08                 	movq	%rax, 0x8(%rcx)
180012a7b: 49 8b 00                    	movq	(%r8), %rax
180012a7e: 49 8b c8                    	movq	%r8, %rcx
180012a81: 48 83 c4 28                 	addq	$0x28, %rsp
180012a85: 48 ff 20                    	jmpq	*(%rax)
180012a88: 49 8b 48 08                 	movq	0x8(%r8), %rcx
180012a8c: 48 85 c9                    	testq	%rcx, %rcx
180012a8f: 74 29                       	je	0x180012aba <C_SetPIN+0xe12a>
180012a91: 48 39 51 10                 	cmpq	%rdx, 0x10(%rcx)
180012a95: 74 11                       	je	0x180012aa8 <C_SetPIN+0xe118>
180012a97: 4c 8b c1                    	movq	%rcx, %r8
180012a9a: 48 8b 49 08                 	movq	0x8(%rcx), %rcx
180012a9e: 48 85 c9                    	testq	%rcx, %rcx
180012aa1: 75 ee                       	jne	0x180012a91 <C_SetPIN+0xe101>
180012aa3: 48 83 c4 28                 	addq	$0x28, %rsp
180012aa7: c3                          	retq
180012aa8: 48 8b 41 08                 	movq	0x8(%rcx), %rax
180012aac: ba 01 00 00 00              	movl	$0x1, %edx
180012ab1: 49 89 40 08                 	movq	%rax, 0x8(%r8)
180012ab5: 48 8b 01                    	movq	(%rcx), %rax
180012ab8: ff 10                       	callq	*(%rax)
180012aba: 48 83 c4 28                 	addq	$0x28, %rsp
180012abe: c3                          	retq
180012abf: cc                          	int3
