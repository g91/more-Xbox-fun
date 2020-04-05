.globl _start
_start:
############################
####   SET VARIABLES   #####
############################
.set	codeLoc, 0xB618			# < this is where our code will be in the hypervisor, it has to be an empty space
.set	hashGen, 0x364			# < the location of the 100f0 hash generation// its just the original call we are replacing
.set	callLoc, 0x1958			# < the call to hashGen address, it will possibly change with dash version
.set	callOrig, 0x4182EA0D 	# < original bits at the call location, we will use this to restore original bits

.set	size,	(6f-0f)			 # < don't edit this
.set    totSize, (9f-0f)         # < don't edit this
.set    memSize, (9f-6f)         # < don't edit this
####   END VARIABLES   #####

####################################################
##########  FIRST JUMP TO OUR CODE   ###############
####################################################
.long	callLoc		# 
.long	0x1			#
	ba		codeLoc
########   END OF THE JUMP PART  #####################

.long	codeLoc
.long	(9f-0f)/4
0:
################################################################
##### LETS COPY FROM HYPERVISOR 0xB618 TO MEMORY ###############
	# r20 source address #0xB618
	lis		%r20, 0
	ori		%r20, %r20, codeLoc
	addi	%r20, %r20, size # 0xB618 + size
	
	# r21 destination #0x800000001C040000
	lis		%r21, 0x3808
	ori		%r21, %r21, 1
	extldi	%r21, %r21, 64,63

	
	li		%r11, memSize	# size of the instructions
	mtctr	%r11
loop_3:
	lbz		%r22, 0(%r20)
	stb		%r22, 0(%r21)
	sync
	isync
	addi	%r20, %r20, 1
	addi	%r21, %r21, 1
	bdnz	loop_3
##########   END COPY CODE   ####################

	# Restore original bits 0x4BFFFE61 at address 0x23B0
	lis		%r11, callOrig@h		
	ori		%r11, %r11, callOrig@l
	li		%r20, callLoc
	stw		%r11, 0(%r20)
	####################################################
	
	# Lets jump to memory location, to continue our code
	lis		%r20, 0x3808
	ori		%r20, %r20, 1
	extldi	%r20, %r20, 64,63
	mtlr	%r20
	blr

6:	
##########################################################
#############   START MEMORY LOCATION CODE    ############

	# First of all, lets clear our code from hypervisor location 0xB618 #
	lis		%r20, 0x8000
	ori		%r20, %r20, 0x100
	sldi	%r20, %r20, 32
	ori		%r20, %r20, codeLoc  # 0x800001000000B618 #< Hypervisor 0xB618 address
	
	li 		%r11, 0x0 # zero r11 register
	addi	%r11, %r11, totSize # total size or our patch (9f-0f)
	mtctr	%r11
loop6_1:
	
	lis		%r21, 0
	stb		%r21, 0(%r20)
	addi	%r20, %r20, 1
	bdnz	loop6_1
	
	# After clearing our code from hypervisor, we are
	# ready to call 0x2210 to generate the 0x100F0 hash
	lis		%r20, 0x8000         # Start Address: 8000
	ori		%r20, %r20, 0x100    # Start Address Additive: 100
	sldi	%r20, %r20, 32       # Start Address Additive: 00000
	ori		%r20, %r20, hashGen  # 0x8000010000002210 #< Hypervisor 0x2210 address

	mtlr	%r20
	blrl
	
7:
	# this will output Nicholasbro>
	lis		%r8, 0x4E69
	ori		%r8, %r8, 0x6368
	stw		%r8, 0(%r1)		#
	
	lis		%r8, 0x6F6C
	ori		%r8, %r8, 0x6173
	stw		%r8, 4(%r1)		# 
	
	lis		%r8, 0x6272
	ori		%r8, %r8, 0x6F3E
	stw		%r8, 8(%r1)		# 
	
	lis		%r8, 0x0D0A
	stw		%r8, 0xC(%r1)	# 
	
	
	mr		%r3, %r1
	li		%r4, 0xE
	
	bl		printAddress

	lis		%r14, 0x1 
	li		%r15, 0

cploop1:
	lbzx	%r13, %r0, %r15
	stbx	%r13, %r3, %r15
	addi	%r15, %r15, 1
	cmplw	%r15, %r14
	bne		cploop1
	
	li %r11, 0x10000
	mr %r4, %r11
	
	bl		printAddress	
	
	lis		%r3, 1
	add		%r3, %r3, %r14
	
	lis		%r14, 1 
	li		%r15, 0
	
	li		%r12, 2
	sldi	%r12, %r12, 32
	oris	%r12, %r12, 1
	
cploop2:
	lbzx	%r13, %r12, %r15
	stbx	%r13, %r3, %r15
	addi	%r15, %r15, 1
	cmplw	%r15, %r14
	bne		cploop2
	
	li %r11, 0x10000
	mr %r4, %r11
	
	bl		printAddress	
	
	lis		%r14, 1
	add		%r3, %r3, %r14
	
	lis		%r14, 1 
	li		%r15, 0
	
	li		%r12, 4
	sldi	%r12, %r12, 32
	oris	%r12, %r12, 2
	
cploop3:
	lbzx	%r13, %r12, %r15
	stbx	%r13, %r3, %r15
	addi	%r15, %r15, 1
	cmplw	%r15, %r14
	bne		cploop3
	

	li %r11, 0x10000
	mr %r4, %r11
	
	bl		printAddress	
	
	lis		%r14, 1
	add		%r3, %r3, %r14
	
	lis		%r14, 1 
	li		%r15, 0
	
	li		%r12, 6
	sldi	%r12, %r12, 32
	oris	%r12, %r12, 3
	
cploop4:
	lbzx	%r13, %r12, %r15
	stbx	%r13, %r3, %r15
	addi	%r15, %r15, 1
	cmplw	%r15, %r14
	bne		cploop4
	
	li %r11, 0x10000
	mr %r4, %r11
	
	bl		printAddress	
	blr

###############################################################################################
##################     PRINT ADDRESS   %r3=address, %r4=size  ###############################
###############################################################################################
printAddress:
	mr		%r30, %r3
	mr 		%r11, %r4			# text size
	mtctr	%r11
cachePrintLoop:
	lbz		%r3, 0(%r30)
putChar:
	lis		%r4, 0x8000
	ori		%r4, %r4, 0x200
	rldicr	%r4, %r4, 32,31
	oris	%r4, %r4, 0xEA00
waitloop:
	lwz		%r5, 0x1018(%r4)  # Wait until character is sent
	rlwinm. %r5, %r5, 0, 6, 6
	beq		waitloop
	slwi	%r3, %r3, 24
	stw		%r3, 0x1014(%r4)  # Send the character
	addi	%r30, %r30, 1
	bdnz+	cachePrintLoop
	blr

9:

	
	