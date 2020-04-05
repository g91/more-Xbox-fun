0:
		mflr	%r12
		std		%r12, -8(%r1)
		std		%r31, -0x10(%r1)
		std		%r30, -0x18(%r1)
		std		%r29, -0x20(%r1)
		std		%r28, -0x28(%r1)
		std		%r27, -0x30(%r1)
		std		%r26, -0x38(%r1)
		std		%r25, -0x40(%r1)
		stdu	%r1, -0xF0(%r1)

		lis		%r5, 0x8000
		sldi    %r6, %r5, 32
		or 		%r25, %r4, %r6

		li		%r5, 0x1FF
		mtctr	%r5
		li 		%r5, 0x80
loop_1:
		lbz		%r12, 0(%r5)
		stb		%r12, 0(%r5)
		dcbst	%r0, %r5
		addi	%r5, %r5, 0x80
		bdnz+	loop_1
		sync
		lis		%r3, 0x8000
		ori		%r3, %r3, 0x200
		sldi	%r3, %r3, 32
		oris	%r3, %r3, 1
		addi	%r3, %r3, 2
		mr 		%r4, %r25
		li 		%r5, 0x3FE
		bl 		dumpAddress

		addi	%r1, %r1, 0xF0
		ld 		%r12, -8(%r1)
		ld 		%r25, -0x40(%r1)
		ld 		%r26, -0x38(%r1)
		ld 		%r27, -0x30(%r1)
		ld 		%r28, -0x28(%r1)
		ld 		%r29, -0x20(%r1)
		ld 		%r30, -0x18(%r1)
		ld 		%r31, -0x10(%r1)
		li 		%r3, 0
		mtlr	%r12
		blr

dumpAddress:
		mtctr %r5
dumpLoop:
		lbz		%r5, 0(%r3)
		stb		%r5, 0(%r4)
		addi	%r4, %r4, 1
		addi	%r3, %r3, 1
		bdnz+	dumpLoop
		blr
9:

#        lis %r11, 1
#        bl loc_1
#loc_1:
#        mfspr %r3, %LR
#        addi %r3, %r3, 52
#loc_2:
#        ldu %r4, 8(%r3)
#        cmpdi %r4, -1
#        beq end
#        mtctr %r11
#loop_1:
#        lbz %r9, 0(%r4)
#        stb %r9, 0(%r8)
#        addi %r4, %r4, 1
#        addi %r8, %r8, 1
#        bdnz loop_1
#        b loc_2
#end:
#        addi %r1, %r1, 0x10
#        nop
#        mtspr %LR, %r12
#        blr
#        .quad 0x8000010000000000
#        .quad 0x8000010200010000
#        .quad 0x8000010400020000
#        .quad 0x8000010600030000
#        .quad 0xFFFFFFFFFFFFFFFF

