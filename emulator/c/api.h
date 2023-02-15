#include "mars.h"

#define MARS_RC_LOCK    3   // not locked or calling thread already locked

// transport function must be provide by user of API
size_t MARS_Transport (
    void *ctx,
    void *txbuf,
    size_t txlen,
    void *rxbuf,
    size_t rxlen);

MARS_RC MARS_ApiInit (void *ctx);
MARS_RC MARS_Lock ();
MARS_RC MARS_Unlock ();
