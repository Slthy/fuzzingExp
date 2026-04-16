libmod_reqtimeout.la: mod_reqtimeout.lo
	$(MOD_LINK) mod_reqtimeout.lo $(MOD_REQTIMEOUT_LDADD)
libmod_filter.la: mod_filter.lo
	$(MOD_LINK) mod_filter.lo $(MOD_FILTER_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_reqtimeout.la libmod_filter.la
shared = 
