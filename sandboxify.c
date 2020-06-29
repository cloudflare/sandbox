#include <stddef.h>
#include <stdlib.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/signal.h>

#include <libgen.h>

#include "sandbox.h"

#define TRACE_OPTS (PTRACE_O_TRACEEXEC)

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s PROG [ARGS]\n", prog);
}

int main(int argc, char **argv)
{
	pid_t child = 0;

	if (argc < 2) {
		usage(basename(argv[0]));
		return EXIT_FAILURE;
	}

	child = fork();
	if (-1 == child) {
		perror("failed to spawn a child process");
		return EXIT_FAILURE;
	}

	if (child) {
		int status = 0;
		pid_t waitp = waitpid(child, &status, 0);

		/* this should be executed after the first SIGSTOP from the child */
		if (ptrace(PTRACE_SETOPTIONS, child, NULL, (TRACE_OPTS | PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_EXITKILL))) {
			perror("failed to suspend seccomp filters for the child");
			/* PTRACE_O_EXITKILL was not yet set, so kill the child manually */
			if (kill(child, SIGKILL)) {
				perror("failed to kill the child process");
			}
			return EXIT_FAILURE;
		}
		
		while (waitp > 0) {
			if (-1 == waitp) {
				perror("waitpid failed");
				return EXIT_FAILURE;
			}
			if (WIFEXITED(status)) {
				fprintf(stderr, "child exited with code %d\n", WEXITSTATUS(status));
				return EXIT_SUCCESS;
			}
			if (WIFSIGNALED(status)) {
				fprintf(stderr, "child was terminated by signal %d\n", WTERMSIG(status));
				return EXIT_SUCCESS;
			}
			if (WIFSTOPPED(status)) {
				if ((SIGTRAP | (PTRACE_EVENT_EXEC << 8)) == (status >> 8)) {
					/* child is stopped before returning from exec */
					/* re-enable seccomp filters and detach */
					if (ptrace(PTRACE_SETOPTIONS, child, NULL, TRACE_OPTS)) {
						perror("failed to re-enable seccomp filters for the child");
						return EXIT_FAILURE;
					}
					if (ptrace(PTRACE_DETACH, child, NULL, NULL)) {
						perror("failed to detach from the child");
						return EXIT_FAILURE;
					}
					return EXIT_SUCCESS;
				}

				if (ptrace(PTRACE_CONT, child, NULL, NULL)) {
					perror("failed to resume the child");
					return EXIT_FAILURE;
				}
			} else {
				fprintf(stderr, "unexpected wait status %x, ignoring...", status);
			}
			waitp = waitpid(child, &status, 0);
		}
	} else {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)) {
			perror("failed to initiate tracing from the child");
			return EXIT_FAILURE;
		}
		/* give the tracer a chance to set options */
		if (raise(SIGSTOP)) {
			perror("failed to send SIGSTOP to the parent");
			return EXIT_FAILURE;
		}

		if (prctl(PR_SET_NO_NEW_PRIVS, 1)) {
			perror("failed to set no_new_privs bit for the child");
			return EXIT_FAILURE;
		}
		setup_seccomp_filter();
		if (execvp(argv[1], &argv[1])) {
			fprintf(stderr, "failed to execute %s: %s\n", argv[1], strerror(errno));
			return EXIT_FAILURE;
		}
	}

	/* unreachable */
	return EXIT_FAILURE;
}
