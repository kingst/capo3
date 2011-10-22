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
#define __MRR_INST_RECORD                       ".byte 0x0F, 0x38, 0x55 ;"
#define __MRR_INST_REPLAY                       ".byte 0x0F, 0x38, 0x56 ;"
#define __MRR_INST_SET_CHUNK_SIZE               ".byte 0x0F, 0x38, 0x57 ;"
#define __MRR_INST_GET_CHUNK_SIZE               ".byte 0x0F, 0x38, 0x58 ;"


////////////////////////////////////////////////////////////////////////////////
// Misc contants
////////////////////////////////////////////////////////////////////////////////

#define MRR_CHUNK_DONE_VECTOR               (0x7e)
#define MRR_FULL_VECTOR                     (0x7f)
#define MRR_FLAG_MASK                       (0x200000)	// bit 21 = ID bit of the FLAGS register

#endif // __MRRHW_IF_H__


