#ifndef SHA2_H
#define SHA2_H

#include <stdint.h>

/* SHA-256 context */
typedef struct {
  uint32_t total[2];
  uint32_t state[8];
  uint8_t buffer[64];
} sha2_context;

/* Function prototypes */
void sha2_starts(sha2_context *ctx);
void sha2_update(sha2_context *ctx, const uint8_t *input, uint32_t length);
void sha2_finish(sha2_context *ctx, uint8_t digest[32]);

/* Helper macros */
#define SHA256_DIGEST_LENGTH 32

#endif /* SHA2_H */
