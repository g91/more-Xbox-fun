0:
	addi	%r12, %r31, 0x180
	ld		%r11, 0(%r12) 
	cmpldi	%r11, 0
	bne		start_loop
	mr		%r11, %r12
start_loop:
	mr		%r9, %r4
	mtctr	%r5
loop_A:
	lbz		%r8, 0(%r9)
	stb		%r8, 8(%r11)
	addi	%r11, %r11, 1
	bdnz+	loop_A
	std		%r4, 8(%r11)
	addi	%r11, %r11, 8
	std		%r11, 0(%r12)
	blr
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
