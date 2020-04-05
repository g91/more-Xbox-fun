0:
		mflr %r11
		lis		%r5, 0x8000
		sldi    %r6, %r5, 32
		or 		%r4, %r4, %r6
		bl loc_0
		bl loc_1
		bl loc_2
		bl loc_3
		b end
loc_0:
		li %r5, 0
		mr %r6, %r5
		b start_loop
loc_1:
		li %r6, 2
		b start_loop
loc_2:
		li %r6, 4
		b start_loop
loc_3:
		li %r6, 6
start_loop:
		sldi %r6, %r6, 32
		or %r5, %r5, %r6
		lis %r6, 1
		mtctr %r6
loop_1:
		lbz		%r6, 0(%r5)
		stb		%r6, 0(%r4)
		addi	%r5, %r5, 1
		addi	%r4, %r4, 1
		bdnz+	loop_1
		clrldi %r5, %r5, 32
		blr
end:
		mtlr %r11
		li %r3, 0
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

