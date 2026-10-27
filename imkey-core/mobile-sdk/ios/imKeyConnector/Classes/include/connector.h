#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/* Inputs are borrowed for the duration of the call. Each returned C string
 * below is Rust-owned: copy it, then call imkey_free_const_string exactly once.
 * Null may be passed to the free function. Never free a borrowed callback input.
 */
const char *call_imkey_api(const char *hex_str);
const char *get_apdu(void);
const char *get_apdu_return(void);
const char *imkey_get_last_err_message(void);
void imkey_clear_err(void);
void imkey_free_const_string(const char *s);
void set_apdu(const char *apdu);
void set_apdu_return(const char *apdu_return);

/* callback receives a borrowed request. The host owns its returned response
 * and must keep it valid until Rust has copied it (before the next serialized
 * callback). Rust never releases host-allocated response memory.
 */
void set_callback(const char *(*callback)(const char *apdu, int32_t timeout));
