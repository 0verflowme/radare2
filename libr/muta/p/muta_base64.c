/* radare - LGPL - Copyright 2016-2025 - rakholiyajenish.07 */

#include <r_lib.h>
#include <r_muta.h>
#include <r_util.h>

static bool base64_set_key(RMutaSession *ms, const ut8 *key, int keylen, int mode, int direction) {
	ms->dir = direction;
	return true;
}

static int base64_get_key_size(RMutaSession *ms) {
	return 0;
}

static bool update(RMutaSession *ms, const ut8 *buf, int len) {
	if (len < 1) {
		return len == 0;
	}
	int olen = 0;
	ut8 *obuf = NULL;
	switch (ms->dir) {
	case R_MUTA_OP_ENCRYPT:
		obuf = (ut8 *)r_base64_encode_dyn (buf, len);
		olen = obuf? (int)strlen ((const char *)obuf): 0;
		break;
	case R_MUTA_OP_DECRYPT:
		obuf = r_base64_decode_dyn ((const char *)buf, len, &olen, false);
		break;
	}
	if (!obuf) {
		return false;
	}
	if (olen > 0) {
		r_muta_session_append (ms, obuf, olen);
	}
	free (obuf);
	return true;
}

RMutaPlugin r_muta_plugin_base64 = {
	.meta = {
		.name = "base64",
		.desc = "Binary to text encoding scheme using 64 ascii characters",
		.author = "rakholiyajenish.07",
		.license = "LGPL-3.0-only" },
	.type = R_MUTA_TYPE_CRYPTO,
	.implements = "base64",
	.set_key = base64_set_key,
	.get_key_size = base64_get_key_size,
	.update = update,
	.end = update
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_CRYPTO,
	.data = &r_muta_plugin_base64,
	.version = R2_VERSION
};
#endif
