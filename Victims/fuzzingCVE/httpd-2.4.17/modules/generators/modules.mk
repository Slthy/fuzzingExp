libmod_status.la: mod_status.lo
	$(MOD_LINK) mod_status.lo $(MOD_STATUS_LDADD)
libmod_autoindex.la: mod_autoindex.lo
	$(MOD_LINK) mod_autoindex.lo $(MOD_AUTOINDEX_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_status.la libmod_autoindex.la
shared = 
