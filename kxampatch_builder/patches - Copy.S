# ==============================
#   Patches
# ==============================
# Add your patches here
# - 81FFA000

.set XLoadImage, 0x826CC730
.set LoadDll, 0x826CAEA8
.set DllStringAdd, 0x8202F7D4

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
