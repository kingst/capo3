#ifndef __MRRHW_IF_H__
#define __MRRHW_IF_H__

////////////////////////////////////////////////////////////////////////////////
// instructions
////////////////////////////////////////////////////////////////////////////////

#define __MRR_INST_DISABLE_CHUNKING             ".byte 0x0F, 0x38, 0x50 ;"
#define __MRR_INST_ENABLE_CHUNKING              ".byte 0x0F, 0x38, 0x51 ;"
#define __MRR_INST_TERMINATE_CHUNK              ".byte 0x0F, 0x38, 0x52 ;"
#define __MRR_INST_FLUSH_BUFFER                 ".byte 0x0F, 0x38, 0x53 ;"
#define __MRR_INST_FLUSH_MRR                    ".byte 0x0F, 0x38, 0x54 ;"

////////////////////////////////////////////////////////////////////////////////
// Misc contants
////////////////////////////////////////////////////////////////////////////////

#define MRR_VECTOR					0x7f
#define MRR_FLAG_MASK				0x200000	// bit 21 = ID bit of the eflags register

#endif // __MRRHW_IF_H__


