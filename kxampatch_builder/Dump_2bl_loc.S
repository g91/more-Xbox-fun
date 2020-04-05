0:
	lis %r11, 1
	bl loc_1
loc_1:
	mfspr %r3, %LR
	addi %r3, %r3, 52
loc_2:
	ldu %r4, 8(%r3)
	cmpdi %r4, -1
	beq end
	mtctr %r11
loop_1:
	lbz %r9, 0(%r4)
	stb %r9, 0(%r8)
	addi %r4, %r4, 1
	addi %r8, %r8, 1
	bdnz loop_1
end:
	addi %r1, %r1, 0x10
	nop
	mtspr %LR, %r12
	blr
	.quad 0x8000020000010000
	.quad 0xFFFFFFFFFFFFFFFF
9:
# branch to correct function


###############################################################################################
##################     PRINT ADDRESS   %r3=address, %r4=size  ###############################
###############################################################################################
#printAddress:
#	li 		%r11, 8			# text size
#	mtctr	%r11
#cachePrintLoop:
#	lbz		%r11, 0(%r12)
#putChar:
#	lis		%r9, 0x8000
#	ori		%r9, %r9, 0x200
#	rldicr	%r9, %r9, 32,31
#	oris	%r9, %r9, 0xEA00
#waitloop:
#	lwz		%r8, 0x1018(%r9)  # Wait until character is sent
#	rlwinm. %r8, %r8, 0, 6, 6
#	beq		waitloop
#	slwi	%r11, %r11, 24
#	stw		%r11, 0x1014(%r9)  # Send the character
#	addi	%r12, %r12, 1
#	bdnz+	cachePrintLoop
#	li		%r11, 0x218
#	blr
9:
#38 80 00 02
