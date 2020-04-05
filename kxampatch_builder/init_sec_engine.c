// assume 
r31 = 0
// assume 
dword r29[]
for(int i = 0;i < 0x14;i++)
{
	// get rng numbers
	for(int i = 0;i < 0x64;i++)
	{
		r11 = *(QWORD*)0x8000020000026008; // HARDWARE_RNG
		r31 = r11 ^ r31;
		if(i < 3)
			continue;
		r3 = unkSub(r31);
		if(r3 < 0x1A)
			continue;
		if(r3 <= 0x26)
			break;
	}
	r10 = 0x1D
	r11 = tb
	r10 = r31/r10
	r10 = r10 * 0x1D
	r10 = r10 - 31
	r10 = r10
	r11 = rol(r11, r10)
	r31 = r11 ^ r31
	r29[i] = r31
}