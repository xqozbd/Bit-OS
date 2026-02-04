#ifndef SYS_AML_H
#define SYS_AML_H

#include <stdint.h>

void aml_init(const uint8_t *aml, uint32_t len);

/* Return pointer to AML object for a Name (DataRefObject) */
const uint8_t *aml_find_name_object(const char *full_path, uint32_t *out_len);

/* Return pointer to AML object returned by Method (Return op) */
const uint8_t *aml_eval_method_return(const char *full_path, uint32_t *out_len);

/* Helper: search any method ending with suffix (e.g. "._PSS") */
const uint8_t *aml_eval_method_return_suffix(const char *suffix, uint32_t *out_len);

#endif /* SYS_AML_H */
