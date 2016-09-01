AUTOMAKE_OPTIONS = foreign

check_PROGRAMS = test_tls_crypt

TESTS = $(check_PROGRAMS)

openvpn_includedir = $(top_srcdir)/include
openvpn_compatdir = $(top_srcdir)/src/compat
openvpn_srcdir = $(top_srcdir)/src/openvpn

test_tls_crypt_CFLAGS  = @TEST_CFLAGS@ \
	-I$(openvpn_includedir) -I$(openvpn_compatdir) -I$(openvpn_srcdir) \
	$(OPTIONAL_CRYPTO_CFLAGS)
test_tls_crypt_LDFLAGS = @TEST_LDFLAGS@ \
	$(OPTIONAL_CRYPTO_LIBS)
test_tls_crypt_SOURCES = test_tls_crypt.c mock_msg.c \
						$(openvpn_srcdir)/buffer.c \
						$(openvpn_srcdir)/crypto.c \
						$(openvpn_srcdir)/crypto_mbedtls.c \
						$(openvpn_srcdir)/crypto_openssl.c \
						$(openvpn_srcdir)/otime.c \
						$(openvpn_srcdir)/packet_id.c \
						$(openvpn_srcdir)/platform.c \
						$(openvpn_srcdir)/tls_crypt.c
