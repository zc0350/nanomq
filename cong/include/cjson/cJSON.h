/*
 * The shared rules engine includes <cjson/cJSON.h>. Point it at the copy of
 * cJSON that NanoMQ compiles into the broker instead of the system libcjson,
 * and build that copy into the plugin as well (see the Makefile).
 *
 * Why it matters: the patched broker is linked with -rdynamic, so its own
 * cJSON_* symbols are in the process's global namespace, and a dlopen()'ed
 * plugin would resolve its cJSON calls there rather than in libcjson. Two
 * cJSON versions with a different struct layout on one object is memory
 * corruption; one version, shared by definition, is not.
 */
#ifndef CONG_CJSON_SHIM_H
#define CONG_CJSON_SHIM_H

#include "nng/supplemental/nanolib/cJSON.h"

#endif /* CONG_CJSON_SHIM_H */
