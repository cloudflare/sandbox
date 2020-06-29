#include "sandbox.h"

static __attribute__((constructor)) void preload_seccomp(void)
{
	setup_seccomp_filter();
}
