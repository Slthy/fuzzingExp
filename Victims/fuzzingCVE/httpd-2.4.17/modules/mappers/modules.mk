libmod_dir.la: mod_dir.lo
	$(MOD_LINK) mod_dir.lo $(MOD_DIR_LDADD)
libmod_alias.la: mod_alias.lo
	$(MOD_LINK) mod_alias.lo $(MOD_ALIAS_LDADD)
DISTCLEAN_TARGETS = modules.mk
static =  libmod_dir.la libmod_alias.la
shared = 
