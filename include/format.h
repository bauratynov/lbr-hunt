/*
 * format.h — human-readable and machine-readable report output.
 */
#ifndef LBR_HUNT_FORMAT_H
#define LBR_HUNT_FORMAT_H

#include "analyzer.h"
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Pretty text report for a terminal. */
void format_report_text (FILE *f, const lbr_report_t *r, double elapsed_s);

/* Single-line JSON object, terminated by '\n'. Safe for
 * append-only log ingestion (one event per line). */
void format_report_jsonl(FILE *f, const lbr_report_t *r, double elapsed_s);

#ifdef __cplusplus
}
#endif

#endif /* LBR_HUNT_FORMAT_H */
