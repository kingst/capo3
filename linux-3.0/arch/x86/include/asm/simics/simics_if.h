/**
 * @file simics_if.h
 *
 * @author Nima Honarmand
 */

#ifndef SIMICS_IF_H_
#define SIMICS_IF_H_

////////////////////////////////////////////////////////////////////////////////
// Markers used for magic calls
////////////////////////////////////////////////////////////////////////////////

#define MRR_MARKERS_BEGIN 			((unsigned)0xB5000000)

#define MRR_MARKER_BREAK_SIM 		((unsigned)(MRR_MARKERS_BEGIN + 0x1))
#define	MRR_MARKER_MESSAGE 			((unsigned)(MRR_MARKERS_BEGIN + 0x2))
#define MRR_MARKER_MESSAGE_INT		((unsigned)(MRR_MARKERS_BEGIN + 0x3))
#define MRR_MARKER_MESSAGE_INT2		((unsigned)(MRR_MARKERS_BEGIN + 0x4))
#define MRR_MARKER_APP_IN			((unsigned)(MRR_MARKERS_BEGIN + 0x5))
#define MRR_MARKER_APP_OUT			((unsigned)(MRR_MARKERS_BEGIN + 0x6))
#define MRR_MARKER_STATS_RESET      ((unsigned)(MRR_MARKERS_BEGIN + 0x7))

#define MRR_SYS_MARKERS_BEGIN 		((unsigned)(MRR_MARKERS_BEGIN + 0x800000))
#define MRR_MARKERS_END 			((unsigned)(MRR_MARKERS_BEGIN + 0xFFFFFF))


#endif // SIMICS_IF_H_
