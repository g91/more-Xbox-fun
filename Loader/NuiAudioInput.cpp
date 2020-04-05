#include "stdafx.h"
#include <nuiapi.h>
#include <NuiAudio.h>

void cbError()
{
	return;
}

void doAudio()
{
	BYTE* nHandle = 0;
	NuiAudioCreate(NUIAUDIO_DEFAULT_PROCESSOR, (PNUIAUDIO_ERROR_CALLBACK)cbError, NUIAUDIO_SPEECH_PIPELINE, nHandle, NULL);
}