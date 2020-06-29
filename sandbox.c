#define _GNU_SOURCE
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <seccomp.h>
#include <string.h>

#include "sandbox.h"

#define SECCOMP_SYSCALL_ALLOW "SECCOMP_SYSCALL_ALLOW"
#define SECCOMP_SYSCALL_DENY "SECCOMP_SYSCALL_DENY"
#define SECCOMP_DEFAULT_ACTION "SECCOMP_DEFAULT_ACTION"

/* hopefully there are no syscalls with names longer than 127 chars */
#define SYSCALL_NAME_MAX_LEN 128

static void add_syscall(scmp_filter_ctx ctx, const char *syscall, uint32_t action)
{
	int syscall_nr = seccomp_syscall_resolve_name(syscall);
	if (__NR_SCMP_ERROR == syscall_nr) {
		fprintf(stderr, "failed to find the syscall number for %s\n", syscall);
		seccomp_release(ctx);
		exit(1);
	}

	if (seccomp_rule_add_exact(ctx, action, syscall_nr, 0)) {
		fprintf(stderr, "failed to add %s to the seccomp filter context\n", syscall);
		seccomp_release(ctx);
		exit(1);
	}
}

void setup_seccomp_filter(void)
{
	scmp_filter_ctx seccomp_ctx;
	uint32_t seccomp_default_action = SCMP_ACT_KILL_PROCESS;
	uint32_t seccomp_syscall_action = SCMP_ACT_ALLOW;
	bool log_not_kill = false;
	char *cur = NULL;
	char syscall_name[SYSCALL_NAME_MAX_LEN] = {0};

	char *syscall_list = getenv(SECCOMP_DEFAULT_ACTION);
	if (syscall_list) {
		log_not_kill = (0 == strncmp(syscall_list, "log", sizeof("log")));
	}

	syscall_list = getenv(SECCOMP_SYSCALL_ALLOW);
	if (syscall_list) {
		seccomp_default_action = log_not_kill ? SCMP_ACT_LOG : SCMP_ACT_KILL_PROCESS;
		seccomp_syscall_action = SCMP_ACT_ALLOW;
	} else if (syscall_list = getenv(SECCOMP_SYSCALL_DENY)) {
		seccomp_default_action = SCMP_ACT_ALLOW;
		seccomp_syscall_action = log_not_kill ? SCMP_ACT_LOG : SCMP_ACT_KILL_PROCESS;
	} else
		return;

	seccomp_ctx = seccomp_init(seccomp_default_action);
	if (NULL == seccomp_ctx) {
		fputs("failed to init seccomp context\n", stderr);
		exit(1);
	}

	cur = syscall_list;
	while (cur = strchrnul(syscall_list, (int)':')) {
		if ((cur - syscall_list) > (SYSCALL_NAME_MAX_LEN - 1)) {
			fputs("syscall name is too long\n", stderr);
			seccomp_release(seccomp_ctx);
			exit(1);
		}

		memcpy(syscall_name, syscall_list, (cur - syscall_list));
		syscall_name[(cur - syscall_list)] = '\0';
		if (0 == strlen(syscall_name)) {
			if ('\0' == *cur)
				break;
			syscall_list = cur + 1;
			continue;
		}

		fprintf(stderr, "adding %s to the process seccomp filter\n", syscall_name);
		add_syscall(seccomp_ctx, syscall_name, seccomp_syscall_action);
		if ('\0' == *cur)
			break;
		else
			syscall_list = cur + 1;
	}

	/* remove our special environment variables, so the sandboxed code
	 * does not see its seccomp configuration
	 */
	if (unsetenv(SECCOMP_DEFAULT_ACTION)) {
		fputs("failed to unset SECCOMP_DEFAULT_ACTION\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}
	if (unsetenv(SECCOMP_SYSCALL_ALLOW)) {
		fputs("failed to unset SECCOMP_SYSCALL_ALLOW\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}
	if (unsetenv(SECCOMP_SYSCALL_DENY)) {
		fputs("failed to unset SECCOMP_SYSCALL_DENY\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}

	if (seccomp_load(seccomp_ctx)) {
		fputs("failed to load the seccomp filter\n", stderr);
		seccomp_release(seccomp_ctx);
		exit(1);
	}

	seccomp_release(seccomp_ctx);
}
