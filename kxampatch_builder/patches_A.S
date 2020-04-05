.globl _start
_start:
############################
####   SET VARIABLES   #####
############################
.set	codeLoc, 0xB618			# < this is where our code will be in the hypervisor, it has to be an empty space
.set	hashGen, 0x364			# < the location of the 100f0 hash generation// its just the original call we are replacing
.set	callLoc, 0x1958			# < the call to hashGen address, it will possibly change with dash version
.set	callOrig, 0x4182EA0D 	# < original bits at the call location, we will use this to restore original bits
.set	scOrig, 0x7DB043A6		# < original bits at start of syscall handler
.set	scEdit, 0x4E800020		# < blr that will be put into the syscall handler
.set	scFunc, 0xBF18			# < where the syscall handler will jump to
.set	scHandler, 0x300
.set	patches, 0xC000

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

	# this will output 100F0 hash
	lis		%r3, 1
	lis		%r29, -0x8000
	ori		%r29, %r29, 0x102
	insrdi	%r3, %r29, 32,0
	ori		%r3, %r3, 0xF0	# 0x80000102000100F0
	li		%r4, 0x10
	bl		printAddress
	
	# this forces the syscall handler to jump back to scFunc
	# NOTE: scFunc contains a FORCE PANIC
	li		%r3, scHandler
	lis		%r4, scEdit@h
	ori		%r4, %r4, scEdit@l
	stw		%r4, 0(%r3)
	li		%r3, 0xBF
	slwi	%r3, %r3, 8
	ori		%r3, %r3, 0x18
	mtlr	%r3
	#li		%r0, 0
	#sc		1	
	
	# this prints the MSR register
	mfmsr	%r5
	std		%r5, 0(%r1)
	mr		%r3, %r1
	li		%r4, 8
	bl		printAddress
	
	# 0xC000 is location of patches
	li		%r3, 0xC0
	slwi	%r3, %r3, 8
	mr		%r12, %r3
	li		%r10, 0xFF
	slwi	%r10, %r10, 8
	ori		%r10, %r10, 0xFF
	slwi	%r10, %r10, 8
	ori		%r10, %r10, 0xFF
	slwi	%r10, %r10, 8
	ori		%r10, %r10, 0xFF	# 0xFFFFFFFF to identify the end of patches
	lis		%r9, 0x8000
	ori		%r9, %r9, 0x100
	sldi	%r9, %r9, 32		# 0x8000010000000000 for HV addressing
	lis		%r8, 0x0D0A
	stw		%r8, 0xC(%r1)
patchLoop_1:
	lwz		%r13, 0(%r12)		# read patch offset
	cmplwi	%r13, %r10			# check for end of patches
	beq		patchDone
	addi	%r12, %r12, 4
	ori		%r19, %r9, %r13
	srdi	%r13, %r13, 16
	oris	%r19, %r19, %r13
	mr		%r13, %r19
	lwz		%r14, 0(%r12)		# read instruction count
	addi	%r12, %r12, 4
	lwz		%r15, 0(%r12)		# read first instruction
	addi	%r12, %r12, 4
	std		%r13, 0(%r1)
	stw		%r14, 8(%r1)
	mr		%r3, %r1
	li		%r4, 0xE
	bl		printAddress		# print patch offset and instruction count
	
	b		jumpReset			# TESTING - REMOVE---------------------------------
	
	mtctr	%r14
patchLoop_2:					# -----program dies somewhere in here-----
	mfctr	%r16				# save the CTR
	stw		%r15, 0(%r1)
	mr		%r3, %r1
	li		%r4, 4
	bl		printAddress		# print current instruction
	mtctr	%r16				# restore the CTR
	stw		%r15, 0(%r13)		# write instruction
	bdz		patchLoop_1			# no more instructions, next patch
	addi	%r13, %r13, 4		
	lwz		%r15, 0(%r12)		# read next instruction
	addi	%r12, %r12, 4
	b		patchLoop_2			# go to write next instruction
patchDone:
	stw		%r13, 0(%r1)
	mr		%r3, %r1
	li		%r4, 0x4
	bl		printAddress		# print 0xFFFFFFFF, tells us we're done with patches
jumpReset:
	li		%r11, 0
	mtspr	0x131, %r11			# clear HSPRG1, makes 0x100 think we're entering for the first time
	li		%r12, 0x100
	mtlr	%r12
	blr							# jump to 0x100 in hypervisor

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

# r3 = dest, r4 = src, r5 = len
cpyXecute:
	mtctr	%r5
#	mtlr	%r3		- let function return so I can do a sanity check
copyloop:
	lwz		%r8, 0(%r4)
	stw		%r8, 0(%r3)
	sync
	isync
	addi	%r4, %r4, 4
	addi	%r3, %r3, 4
	bdnz	copyloop
	blr
	
9:

.long scFunc
.long (9f-0f)/4
0:
	mfdsisr	%r4
	mfdar	%r5
	std		%r4, 0(%r1)
	std		%r5, 8(%r1)
	mr		%r3, %r1
	li		%r4, 0xC
	bl		printAddress
forcePanic:
	li		%r0, 0
	mtctr	%r0
	b		forcePanic
9:

.long patches
.long (9f-0f)/4
0:
.long 0x00001880
.long 0x00000001
.long 0x4800B4FB
.long 0x000000F0
.long 0x00000004
.long 0x00000000
.long 0x00000000
.long 0x00000000
.long 0x00000000
.long 0x000011BC
.long 0x00000001
.long 0x4800154E
.long 0x0000154C
.long 0x00000004
.long 0x38800007
.long 0x7C212078
.long 0x7C35EBA6
.long 0x480011C2
.long 0x00003120
.long 0x00000001
.long 0x60000000
.long 0x0000A560
.long 0x00000002
.long 0x38600001
.long 0x4E800020
.long 0x0002A30C
.long 0x00000002
.long 0x60000000
.long 0x60000000
.long 0x0002AA80
.long 0x00000001
.long 0x60000000
.long 0x0002AA8C
.long 0x00000001
.long 0x60000000
.long 0x0000B4F8
.long 0x00000048
.long 0x7D0802A6
.long 0xA0600006
.long 0x38800021
.long 0x7C632078
.long 0xB0600006
.long 0x38600021
.long 0x4800B527
.long 0x3860000A
.long 0x4800B527
.long 0x7D0803A6
.long 0x480002DA
.long 0x3C808000
.long 0x60840200
.long 0x788407C6
.long 0x6484EA00
.long 0x5463C00E
.long 0x90641014
.long 0x80641018
.long 0x5463018D
.long 0x4182FFF8
.long 0x4E800020
.long 0x3D607262
.long 0x616B7472
.long 0x7F035840
.long 0x419A0008
.long 0x48001CCA
.long 0x2B040004
.long 0x41990094
.long 0x419A0044
.long 0x38A0154C
.long 0x3CC03880
.long 0x2B040002
.long 0x409A000C
.long 0x60C60007
.long 0x4800000C
.long 0x2B040003
.long 0x409A001C
.long 0x38000000
.long 0x90C50000
.long 0x7C00286C
.long 0x7C002FAC
.long 0x7C0004AC
.long 0x4C00012C
.long 0x38600001
.long 0x4E800020
.long 0x7D8802A6
.long 0xF981FFF8
.long 0xF821FFF1
.long 0x7CA803A6
.long 0x7CE903A6
.long 0x80860000
.long 0x90850000
.long 0x7C00286C
.long 0x7C002FAC
.long 0x7C0004AC
.long 0x4C00012C
.long 0x38A50004
.long 0x38C60004
.long 0x4200FFE0
.long 0x4E800020
.long 0x38210010
.long 0xE981FFF8
.long 0x7D8803A6
.long 0x4E800020
.long 0x2B040005
.long 0x409A0014
.long 0x7CC33378
.long 0x7CA42B78
.long 0x7CE53B78
.long 0x4800A882
.long 0x38600002
.long 0x4E800020
.long 0x00015E60
.long 0x00000001
.long 0x0000B54C
.long 0x00006BB0
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x00006C48
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x00006C98
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x00006D08
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x00006D58
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0000813C
.long 0x00000001
.long 0x48000030
.long 0x000070BC
.long 0x00000001
.long 0x38600001
.long 0x00007268
.long 0x00000001
.long 0x38600000
.long 0x000072B4
.long 0x00000001
.long 0x60000000
.long 0x000072C4
.long 0x00000001
.long 0x60000000
.long 0x000072EC
.long 0x00000002
.long 0x60000000
.long 0x39600001
.long 0x00024D58
.long 0x00000002
.long 0x38600001
.long 0x4E800020
.long 0x000264F0
.long 0x00000001
.long 0x38600001
.long 0x00029B08
.long 0x0000000E
.long 0x2B3C0000
.long 0x419A0030
.long 0x2F030000
.long 0x409A0010
.long 0x388000F0
.long 0x48000018
.long 0x60000000
.long 0x2B1D0000
.long 0x389F0440
.long 0x409A0008
.long 0x38800054
.long 0x7F83E378
.long 0x4BFF65C1
.long 0x3BE00000
.long 0x0002B770
.long 0x00000001
.long 0x60000000
.long 0x0002C0B0
.long 0x00000001
.long 0x38600000
.long 0x0002C3A0
.long 0x00000001
.long 0x60000000
.long 0x0003089C
.long 0x00000004
.long 0x409A0008
.long 0x3BA00000
.long 0x60000000
.long 0x60000000
.long 0x000304E8
.long 0x00000001
.long 0x60000000
.long 0x000304FC
.long 0x00000001
.long 0x60000000
.long 0x0007B160
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0007BCF8
.long 0x00000001
.long 0x38600001
.long 0x0007BE08
.long 0x00000001
.long 0x38600000
.long 0x0007BE70
.long 0x00000001
.long 0x39600000
.long 0x0007BEC0
.long 0x00000001
.long 0x39600000
.long 0x0007A748
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x000945F0
.long 0x00000001
.long 0x3AE00010
.long 0x00098F18
.long 0x00000001
.long 0x2B0B00FF
.long 0x000988FC
.long 0x00000005
.long 0x38600000
.long 0x60000000
.long 0x60000000
.long 0x60000000
.long 0x60000000
.long 0x0010ACE0
.long 0x00000002
.long 0x38600001
.long 0x4E800020
.long 0x0010B7D8
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0010BAB8
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0010BF80
.long 0x00000002
.long 0x38600001
.long 0x4E800020
.long 0x0010C188
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0010C138
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0010C2C8
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0010C448
.long 0x00000002
.long 0x38600000
.long 0x4E800020
.long 0x0010CF70
.long 0x00000005
.long 0x2B050000
.long 0x38600001
.long 0x419A0008
.long 0x90650000
.long 0x4E800020
.long 0x001129E0
.long 0x00000002
.long 0x38600001
.long 0x4E800020
.long 0x000E27A4
.long 0x00000001
.long 0x48000054
.long 0x000E281C
.long 0x00000003
.long 0x835C0098
.long 0x60000000
.long 0x60000000
.long 0x0015EA70
.long 0x00000002
.long 0x38600001
.long 0x4E800020
.long 0x0010CF90
.long 0x0000002C
.long 0x40980008
.long 0x4E800020
.long 0x3C608010
.long 0x3CA00000
.long 0x38800000
.long 0x60840008
.long 0x6063D020
.long 0x38C00000
.long 0x4BF6FF91
.long 0x38600000
.long 0x3C808010
.long 0x6084D03C
.long 0x4C00012C
.long 0x90640000
.long 0x4BF54414
.long 0x38A10054
.long 0x3CE08010
.long 0x60E7D03C
.long 0x81070000
.long 0x4C00012C
.long 0x2B080000
.long 0x419A000C
.long 0x7FFFFB78
.long 0x4BFFFFEC
.long 0x4E800020
.long 0x2B030014
.long 0x409A0024
.long 0x3CE08010
.long 0x60E7D03C
.long 0x81070000
.long 0x4C00012C
.long 0x2B080000
.long 0x419A000C
.long 0x7FFFFB78
.long 0x4BFFFFEC
.long 0x4BFFC444
.long 0x5C446576
.long 0x6963655C
.long 0x466C6173
.long 0x685C6C61
.long 0x756E6368
.long 0x2E786578
.long 0x00000000
.long 0x12345678
.long 0x000613CC
.long 0x00000001
.long 0x480ABBC5
.long 0x0007CF78
.long 0x00000001
.long 0x48090055
.long 0x00109EC0
.long 0x00000001
.long 0x48003134
.long 0xFFFFFFFF
9:
.long 0xFFFFFFFF
	
	