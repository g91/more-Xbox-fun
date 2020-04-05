# ==============================
#   Patches
# ==============================
# Add your patches here
# - 81FFA000

.set XLoadImage, 0x82536A00
.set LoadDll, 0x825363A0
.set DllStringAdd, 0x82004498

		.globl _start

_start:

# =============================
#   Sample Patch
# =============================

.long DllStringAdd
.long (9f - 0f)/4
0:
	.string "game:\\Kratistos.dll"
	.align 4
9:

.long LoadDll
.long (9f - 0f)/4
0:
	lis %r11, DllStringAdd@h
	ori %r3, %r11, DllStringAdd@l
	bl (XLoadImage - (LoadDll + 0x8))
9:

# DO NOT INSERT ANYTHING BELOW THIS POINT!!!
# ===========================
.long 0xFFFFFFFF
