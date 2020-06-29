COMMON_CFLAGS := -fPIC -Ilibseccomp/include

all: libsandbox.so sandboxify

%.o: %.c
	$(CC) -c $(COMMON_CFLAGS) -o $@ $<

# the custom linker script should hide the symbols from the included
# static libseccomp to avoid potential clash with the libseccomp the
# sandboxed process might be using
libsandbox.so: sandbox.o preload.o
	$(CC) -shared -Wl,--version-script=libsandbox.version -o $@ $^ libseccomp/src/.libs/libseccomp.a

sandboxify: sandboxify.o sandbox.o
	$(CC) -o $@ $^ libseccomp/src/.libs/libseccomp.a
