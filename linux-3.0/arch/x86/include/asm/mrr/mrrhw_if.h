#ifndef __MRRHW_IF_H__
#define __MRRHW_IF_H__

////////////////////////////////////////////////////////////////////////////////
// Markers used for magic calls
////////////////////////////////////////////////////////////////////////////////

#define MRR_MARKERS_BEGIN 			((unsigned)0xB5000000)

#define MRR_MARKER_BREAK_SIM 		((unsigned)(MRR_MARKERS_BEGIN + 0x1))
#define	MRR_MARKER_MESSAGE 			((unsigned)(MRR_MARKERS_BEGIN + 0x2))
#define MRR_MARKER_MESSAGE_INT		((unsigned)(MRR_MARKERS_BEGIN + 0x3))
#define MRR_MARKER_APP_IN			((unsigned)(MRR_MARKERS_BEGIN + 0x4))
#define MRR_MARKER_APP_OUT			((unsigned)(MRR_MARKERS_BEGIN + 0x5))
#define MRR_MARKER_STATS_RESET      ((unsigned)(MRR_MARKERS_BEGIN + 0x6))

#define MRR_SYS_MARKERS_BEGIN 		((unsigned)(MRR_MARKERS_BEGIN + 0x800000))
#define MRR_MARKERS_END 			((unsigned)(MRR_MARKERS_BEGIN + 0xFFFFFF))

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


