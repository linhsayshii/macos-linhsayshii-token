
.local/oneca-windows/extracted/app/TokenMgr.dll:	file format coff-i386

Disassembly of section .text:

10001000 <.text>:
100052f0: 83 ec 50                     	subl	$0x50, %esp
100052f3: 53                           	pushl	%ebx
100052f4: 89 44 24 14                  	movl	%eax, 0x14(%esp)
100052f8: 8b c1                        	movl	%ecx, %eax
100052fa: 55                           	pushl	%ebp
100052fb: c7 44 24 14 01 00 00 00      	movl	$0x1, 0x14(%esp)
10005303: c6 44 24 0b 01               	movb	$0x1, 0xb(%esp)
10005308: 8d 68 01                     	leal	0x1(%eax), %ebp
1000530b: 33 db                        	xorl	%ebx, %ebx
1000530d: 8d 49 00                     	leal	(%ecx), %ecx
10005310: 8a 10                        	movb	(%eax), %dl
10005312: 40                           	incl	%eax
10005313: 3a d3                        	cmpb	%bl, %dl
10005315: 75 f9                        	jne	0x10005310 <.text+0x4310>
10005317: 2b c5                        	subl	%ebp, %eax
10005319: 8d 54 24 14                  	leal	0x14(%esp), %edx
1000531d: 89 54 24 2c                  	movl	%edx, 0x2c(%esp)
10005321: ba 04 00 00 00               	movl	$0x4, %edx
10005326: 8d 6c 24 0b                  	leal	0xb(%esp), %ebp
1000532a: 89 4c 24 50                  	movl	%ecx, 0x50(%esp)
1000532e: 40                           	incl	%eax
1000532f: 52                           	pushl	%edx
10005330: 89 6c 24 3c                  	movl	%ebp, 0x3c(%esp)
10005334: 89 44 24 58                  	movl	%eax, 0x58(%esp)
10005338: 8b 47 04                     	movl	0x4(%edi), %eax
1000533b: 8d 4c 24 2c                  	leal	0x2c(%esp), %ecx
1000533f: 8d 6c 24 1c                  	leal	0x1c(%esp), %ebp
10005343: 51                           	pushl	%ecx
10005344: 89 5c 24 30                  	movl	%ebx, 0x30(%esp)
10005348: 89 54 24 38                  	movl	%edx, 0x38(%esp)
1000534c: c7 44 24 3c 01 00 00 00      	movl	$0x1, 0x3c(%esp)
10005354: c7 44 24 44 01 00 00 00      	movl	$0x1, 0x44(%esp)
1000535c: c7 44 24 48 67 00 00 80      	movl	$0x80000067, 0x48(%esp) # imm = 0x80000067
10005364: 89 6c 24 4c                  	movl	%ebp, 0x4c(%esp)
10005368: 89 54 24 50                  	movl	%edx, 0x50(%esp)
1000536c: c7 44 24 54 66 00 00 80      	movl	$0x80000066, 0x54(%esp) # imm = 0x80000066
10005374: 8b 50 6a                     	movl	0x6a(%eax), %edx
10005377: 56                           	pushl	%esi
10005378: ff d2                        	calll	*%edx
1000537a: 83 c4 0c                     	addl	$0xc, %esp
1000537d: 85 c0                        	testl	%eax, %eax
1000537f: 75 5a                        	jne	0x100053db <.text+0x43db>
10005381: 8b 47 04                     	movl	0x4(%edi), %eax
10005384: 8d 4c 24 0c                  	leal	0xc(%esp), %ecx
10005388: 51                           	pushl	%ecx
10005389: 6a 01                        	pushl	$0x1
1000538b: 8d 54 24 18                  	leal	0x18(%esp), %edx
1000538f: 52                           	pushl	%edx
10005390: 89 5c 24 1c                  	movl	%ebx, 0x1c(%esp)
10005394: c7 44 24 18 01 00 00 00      	movl	$0x1, 0x18(%esp)
1000539c: 8b 40 6e                     	movl	0x6e(%eax), %eax
1000539f: 56                           	pushl	%esi
100053a0: ff d0                        	calll	*%eax
100053a2: 83 c4 10                     	addl	$0x10, %esp
100053a5: 56                           	pushl	%esi
100053a6: 85 c0                        	testl	%eax, %eax
100053a8: 74 18                        	je	0x100053c2 <.text+0x43c2>
100053aa: 8b 4f 04                     	movl	0x4(%edi), %ecx
100053ad: 8b 51 72                     	movl	0x72(%ecx), %edx
100053b0: ff d2                        	calll	*%edx
100053b2: 83 c4 04                     	addl	$0x4, %esp
100053b5: 5d                           	popl	%ebp
100053b6: b8 01 00 00 00               	movl	$0x1, %eax
100053bb: 5b                           	popl	%ebx
100053bc: 83 c4 50                     	addl	$0x50, %esp
100053bf: c2 08 00                     	retl	$0x8
100053c2: 8b 47 04                     	movl	0x4(%edi), %eax
100053c5: 8b 48 72                     	movl	0x72(%eax), %ecx
100053c8: ff d1                        	calll	*%ecx
100053ca: 83 c4 04                     	addl	$0x4, %esp
100053cd: 39 5c 24 0c                  	cmpl	%ebx, 0xc(%esp)
100053d1: 74 08                        	je	0x100053db <.text+0x43db>
100053d3: 8b 6c 24 10                  	movl	0x10(%esp), %ebp
100053d7: 3b eb                        	cmpl	%ebx, %ebp
100053d9: 75 0d                        	jne	0x100053e8 <.text+0x43e8>
100053db: 5d                           	popl	%ebp
100053dc: b8 01 00 00 00               	movl	$0x1, %eax
100053e1: 5b                           	popl	%ebx
100053e2: 83 c4 50                     	addl	$0x50, %esp
100053e5: c2 08 00                     	retl	$0x8
100053e8: 8b 57 04                     	movl	0x4(%edi), %edx
100053eb: 6a 01                        	pushl	$0x1
100053ed: 8d 44 24 20                  	leal	0x20(%esp), %eax
100053f1: 50                           	pushl	%eax
100053f2: c7 44 24 24 11 00 00 00      	movl	$0x11, 0x24(%esp)
100053fa: 89 5c 24 28                  	movl	%ebx, 0x28(%esp)
100053fe: 89 5c 24 2c                  	movl	%ebx, 0x2c(%esp)
10005402: 8b 4a 62                     	movl	0x62(%edx), %ecx
10005405: 55                           	pushl	%ebp
10005406: 56                           	pushl	%esi
10005407: ff d1                        	calll	*%ecx
10005409: 83 c4 10                     	addl	$0x10, %esp
1000540c: 85 c0                        	testl	%eax, %eax
1000540e: 74 0d                        	je	0x1000541d <.text+0x441d>
10005410: 5d                           	popl	%ebp
10005411: b8 02 00 00 00               	movl	$0x2, %eax
10005416: 5b                           	popl	%ebx
10005417: 83 c4 50                     	addl	$0x50, %esp
1000541a: c2 08 00                     	retl	$0x8
1000541d: 8b 54 24 5c                  	movl	0x5c(%esp), %edx
10005421: 3b d3                        	cmpl	%ebx, %edx
10005423: 75 14                        	jne	0x10005439 <.text+0x4439>
10005425: 8b 44 24 60                  	movl	0x60(%esp), %eax
10005429: 8b 54 24 24                  	movl	0x24(%esp), %edx
1000542d: 5d                           	popl	%ebp
1000542e: 89 10                        	movl	%edx, (%eax)
10005430: 33 c0                        	xorl	%eax, %eax
10005432: 5b                           	popl	%ebx
10005433: 83 c4 50                     	addl	$0x50, %esp
10005436: c2 08 00                     	retl	$0x8
10005439: 8b 44 24 24                  	movl	0x24(%esp), %eax
1000543d: 8b 4c 24 60                  	movl	0x60(%esp), %ecx
10005441: 39 01                        	cmpl	%eax, (%ecx)
10005443: 89 01                        	movl	%eax, (%ecx)
10005445: 73 0d                        	jae	0x10005454 <.text+0x4454>
10005447: 5d                           	popl	%ebp
10005448: b8 03 00 00 00               	movl	$0x3, %eax
1000544d: 5b                           	popl	%ebx
1000544e: 83 c4 50                     	addl	$0x50, %esp
