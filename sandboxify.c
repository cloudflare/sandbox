#define _GNU_SOURCE

#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/signal.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <libgen.h>

#include "sandbox.h"

#define TRACE_OPTS (PTRACE_O_TRACEEXEC)

static void usage(const char *prog)
{
	fprintf(stderr, "usage: %s PROG [ARGS]\n", prog);
}

int main(int argc, char **argv)
{
	int pipefds[2];
	char data = '\0';
	pid_t child = 0;
	pid_t parent = getpid();

	if (argc < 2) {
		usage(basename(argv[0]));
		return EXIT_FAILURE;
	}

	if (pipe2(pipefds, O_CLOEXEC)) {
		perror("failed to setup control pipes");
		return EXIT_FAILURE;
	}

	child = fork();
	if (-1 == child) {
		perror("failed to spawn a child process");
		return EXIT_FAILURE;
	}

	if (child) {
		/* we created the child process */
		int status = 0;
		pid_t waitp;

		if (close(pipefds[1])) {
			perror("closing pipe end");
			return EXIT_FAILURE;
		}

		/* allow the child to use PTRACE on us */
		if (prctl(PR_SET_PTRACER, child, 0, 0, 0) < 0) {
			/* if YAMA LSM support is not compiled in the kernel this will fail
			 * with EINVAL. this is fine, we can continue */
			if (errno != EINVAL) {
				perror("unable to nominate child as current process tracer");
				return EXIT_FAILURE;
			}
		}

		/* give the tracer a chance to set options */
		if (read(pipefds[0], &data, 1) < 1) {
			/* any short read indicates an abnormal failure in the child */
			fprintf(stderr, "child exited\n");
			return EXIT_FAILURE;
		}

		if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
			perror("failed to set no_new_privs bit for the parent");
			return EXIT_FAILURE;
		}

		setup_seccomp_filter();

		if (execvp(argv[1], &argv[1])) {
			fprintf(stderr, "failed to execute %s: %s\n",
					argv[1], strerror(errno));
			return EXIT_FAILURE;
		}

	} else {
		int status = 0;
		pid_t waitp;

		if (close(pipefds[0])) {
			perror("closing pipe end");
			return EXIT_FAILURE;
		}

		/* ensure we are killed if the parent exits */
		if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0) {
			perror("failed to set pdeathsig bit for the child");
			return EXIT_FAILURE;
		}
		/* attach to the parent and interrupt it */
		/* may fail because of missing CAP_SYS_PTRACE or YAMA LSM mode. */
		if (ptrace(PTRACE_ATTACH, parent, NULL, NULL)) {
			perror("failed to attach to parent");
			return EXIT_FAILURE;
		}

		if ((waitp = waitpid(parent, &status, 0)) < 0) {
			perror("waitpid failed");
			return EXIT_FAILURE;
		}

		/* this should be executed after the first ptrace-stop from the parent
		 * which the waitpid() above ensures. */
		/* may fail because of missing CAP_SYS_ADMIN */
		if (ptrace(PTRACE_SETOPTIONS, parent, NULL, (TRACE_OPTS | PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_EXITKILL))) {
			perror("failed to suspend seccomp filters for the parent");
			/* PTRACE_O_EXITKILL was not yet set, but it should catch this
			 * child's exit. */
			return EXIT_FAILURE;
		}

		/* free the parent from its read() */
		if (write(pipefds[1], &data, 1) < 1) {
			perror("bad write on control pipe");
			return EXIT_FAILURE;
		}

		while (waitp > 0) {
			if (-1 == waitp) {
				perror("waitpid failed");
				return EXIT_FAILURE;
			}
			/* note we probably will never see either of the EXITED/SIGNALED
			 * cases because of PR_SET_PDEATHSIG.  */
			if (WIFEXITED(status)) {
				fprintf(stderr, "parent exited with code %d\n", WEXITSTATUS(status));
				return EXIT_SUCCESS;
			}
			if (WIFSIGNALED(status)) {
				fprintf(stderr, "parent was terminated by signal %d\n", WTERMSIG(status));
				return EXIT_SUCCESS;
			}

			if (WIFSTOPPED(status)) {
				if ((SIGTRAP | (PTRACE_EVENT_EXEC << 8)) == (status >> 8)) {
					/* parent is stopped before returning from exec. */
					/* re-enable seccomp filters and detach */
					if (ptrace(PTRACE_SETOPTIONS, parent, NULL, TRACE_OPTS)) {
						perror("failed to re-enable seccomp filters for the parent");
						return EXIT_FAILURE;
					}
					if (ptrace(PTRACE_DETACH, parent, NULL, NULL)) {
						perror("failed to detach from the parent");
						return EXIT_FAILURE;
					}
					return EXIT_SUCCESS;
				}
				if (ptrace(PTRACE_CONT, parent, NULL, NULL)) {
					perror("failed to resume the parent");
					return EXIT_FAILURE;
				}
			} else {
				fprintf(stderr, "unexpected wait status %x, ignoring...", status);
			}
			waitp = waitpid(parent, &status, 0);
		}
	}

	/* unreachable */
	return EXIT_FAILURE;
}
