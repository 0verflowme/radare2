/* debugbochs  - LGPL - Copyright 2016-2025 - SkUaTeR */

#include <r_debug.h>
#include <r_core.h>
#include <libbochs.h>

typedef struct {
	libbochs_t desc;
} RIOBochs;

// size of the cached register arena, the profile below fits in it
#define BOCHS_SAVEREGS_SIZE 1024

typedef struct plugin_data_t {
	bool bCapturaRegs;
	bool bStep;
	bool bBreak;
	bool bAjusta;
	ut8 saveRegs[BOCHS_SAVEREGS_SIZE];
	ut64 ripStop;
	libbochs_t *desc; // owned by the io plugin, set while attached
} PluginData;

static bool is_bochs(RDebug *dbg) {
	RIODesc *d = dbg? R_UNWRAP3 (dbg, iob.io, desc): NULL;
	if (d && d->plugin && d->plugin->meta.name && !strcmp ("bochs", d->plugin->meta.name)) {
		return true;
	}
	R_LOG_ERROR ("the iodesc data is not bochs friendly");
	return false;
}

// plugin data of an attached bochs session, every libbochs call needs its desc
static PluginData *get_pd(RDebug *dbg) {
	PluginData *pd = is_bochs (dbg)? R_UNWRAP3 (dbg, current, plugin_data): NULL;
	if (pd && !pd->desc) {
		R_LOG_ERROR ("not attached to bochs");
		return NULL;
	}
	return pd;
}

static bool r_debug_bochs_breakpoint(RBreakpoint *bp, RBreakpointItem *b, bool set) {
	R_LOG_DEBUG ("bochs_breakpoint");
	if (!bp || !b) {
		return false;
	}
	PluginData *pd = get_pd (bp->user);
	if (!pd) {
		return false;
	}
	char cmd[64];
	if (set) {
		snprintf (cmd, sizeof (cmd), "lb 0x%x", (ut32)b->addr);
		bochs_send_cmd (pd->desc, cmd, true);
		pd->bCapturaRegs = true;
		return true;
	}
	/*
	Num Type           Disp Enb Address
	  1 lbreakpoint    keep y   0x0000000000007c00
	  2 lbreakpoint    keep y   0x0000000000007c00
	<bochs:39>
	*/
	bochs_send_cmd (pd->desc, "blist", true);
	const char *data = pd->desc->data;
	if (!r_str_startswith (data, "Num Type")) {
		return true;
	}
	// rows are 48 chars wide, the enable flag sits at column 24 and the 18
	// char address at column 28, so only walk rows that are fully present
	const int lenRec = strlen (data);
	int i;
	for (i = 37; i + 46 <= lenRec && data[i] != '<'; i += 48) {
		if (data[i + 24] == 'y' && r_num_get (NULL, data + i + 28) == b->addr) {
			snprintf (cmd, sizeof (cmd), "d %d", atoi (data + i));
			bochs_send_cmd (pd->desc, cmd, true);
			break;
		}
	}
	return true;
}

static bool bochs_reg_read(RDebug *dbg, int type, ut8 *buf, int size) {
	PluginData *pd = get_pd (dbg);
	if (!pd || size < 1) {
		return false;
	}
	const int cached = R_MIN (size, BOCHS_SAVEREGS_SIZE);
	if (!pd->bCapturaRegs) {
		memcpy (buf, pd->saveRegs, cached);
		return true;
	}
	char strReg[19];
	ut64 val, valRIP = 0;
	//r14: 00000000_00000000 r15: 00000000_00000000
	//rip: 00000000_0000e07b
	//"eflags 0x00000046: id vip vif ac vm rf nt IOPL=0 of df if tf sf ZF af PF cf"
	//<bochs:109>return -1;
	bochs_send_cmd (pd->desc, "regs", true);
	const char *data = pd->desc->data;
	const int lenRec = strlen (data);
	int i = 0, pos = 0x78;
	// a register token is "rNN: hhhhhhhh_hhhhhhhh", exactly 22 chars, and the
	// copies below reach i+21, so require the whole token to be present
	while (i + 22 <= lenRec) {
		if (data[i] != 'r' || data[i + 3] != ':') {
			i++;
			continue;
		}
		if (pos + 8 > size) {
			// the stub sent more registers than the arena can hold
			break;
		}
		snprintf (strReg, sizeof (strReg), "0x%.8s%.8s", data + i + 5, data + i + 14);
		val = r_num_get (NULL, strReg);
		memcpy (buf + pos, &val, 8);
		// guardamos el valor del rip para ajustarlo al obtener el CS
		if (r_str_startswith (data + i, "rip")) {
			valRIP = val;
		}
		pos += 8;
		i += 22;
	}

	bochs_send_cmd (pd->desc, "info cpu", true);
	if (strstr (data, "PC_32")) {
		pd->bAjusta = true;
	} else if (strstr (data, "PC_80") || strstr (data, "PC_64")) {
		pd->bAjusta = false;
	} else {
		R_LOG_ERROR ("unknown mode: %s", data);
	}
	/*
	   es:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
	   Data segment, base=0x00000000, limit=0x0000ffff, Read/Write, Accessed
	   cs:0xf000, dh=0xff0093ff, dl=0x0000ffff, valid=7
	   Data segment, base=0xffff0000, limit=0x0000ffff, Read/Write, Accessed
	   ss:0x0000, dh=0x00009300, dl=0x0000ffff, valid=7
	   ...
	   gdtr:base=0x0000000000000000, limit=0xffff
	   idtr:base=0x0000000000000000, limit=0xffff
	*/
	bochs_send_cmd (pd->desc, "sreg", true);
	const char *segs[] = { "es:0x", "cs:0x", "ss:0x", "ds:0x", "fs:0x", "gs:0x", NULL };
	int n;
	// each segment has a fixed slot in the profile, so advance even when missing
	for (n = 0, pos = 0x38; segs[n] && pos + 2 <= size; n++, pos += 2) {
		const char *x = strstr (data, segs[n]);
		if (x) {
			val = r_num_get (NULL, x + 3);
			memcpy (buf + pos, &val, 2);
			if (pd->bAjusta && n == 1) {
				valRIP += val * 0x10; // desplazamos CS y lo añadimos a RIP
			}
		}
	}
	// Cheat para evitar traducciones de direcciones: cs:ip lives in the virtual "csip"
	if (size >= 8) {
		val = pd->ripStop? pd->ripStop: valRIP;
		memcpy (buf, &val, 8);
	}
	memcpy (pd->saveRegs, buf, cached);
	pd->bCapturaRegs = false;
	return true;
}

static bool bochs_reg_write(RDebug *dbg, int type, const ut8 *buf, int size) {
	return false;
}

static RList *r_debug_bochs_map_get(RDebug* dbg) { //TODO
	if (!is_bochs (dbg)) {
		return NULL;
	}
	RList *list = r_list_newf ((RListFree)r_debug_map_free);
	r_list_append (list, r_debug_map_new ("fake", 0, UT32_MAX, 0, 0));
	return list;
}

static bool r_debug_bochs_step(RDebug *dbg) {
	PluginData *pd = get_pd (dbg);
	if (!pd) {
		return false;
	}
	bochs_send_cmd (pd->desc, "s", true);
	pd->bCapturaRegs = true;
	pd->bStep = true;
	return true;
}

static bool r_debug_bochs_continue(RDebug *dbg, int pid, int tid, int sig) {
	PluginData *pd = get_pd (dbg);
	if (!pd) {
		return false;
	}
	bochs_send_cmd (pd->desc, "c", false);
	pd->bCapturaRegs = true;
	pd->bBreak = false;
	return true;
}

static void bochs_debug_break(void *user) {
	R_LOG_INFO ("bochs_debug_break: Sending break");
	PluginData *pd = get_pd (user);
	if (pd) {
		bochs_cmd_stop (pd->desc);
		pd->bBreak = true;
	}
}

static RDebugReasonType r_debug_bochs_wait(RDebug *dbg, int pid) {
	PluginData *pd = get_pd (dbg);
	if (!pd) {
		return R_DEBUG_REASON_ERROR;
	}
	RCore *core = dbg->coreb.core;
	char *data = pd->desc->data;
	if (pd->bStep) {
		pd->bStep = false;
	} else {
		r_cons_break_push (core->cons, bochs_debug_break, dbg);
		int i = 500;
		for (;;) {
			bochs_wait (pd->desc);
			if (pd->bBreak) {
				if (data[0]) {
					R_LOG_INFO ("ctrl+c %s", data);
					pd->bBreak = false;
					break;
				}
				if (!--i) {
					pd->bBreak = false;
					R_LOG_INFO ("empty ctrl+c");
					break;
				}
			} else if (data[0]) {
				break; // stop on breakpoint
			}
		}
		r_cons_break_pop (core->cons);
	}
	// Next at t=394241428
	// (0) [0x000000337635] 0020:0000000000337635 (unk. ctxt): add eax, esi              ; 03c6
	pd->ripStop = 0;
	const char *x = strstr (data, "Next at");
	if (x && (x = strstr (x, "[0x"))) {
		// the hex parser stops at the closing bracket, whatever its distance
		pd->ripStop = r_num_get (NULL, x + 1);
	}
	data[0] = 0;
	return R_DEBUG_REASON_NONE;
}

static bool r_debug_bochs_stop(RDebug *dbg) {
	return true;
}

static bool r_debug_bochs_attach(RDebug *dbg, int pid) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}
	pd->desc = NULL;
	dbg->options.swstep = false;
	RIOBochs *g = is_bochs (dbg)? dbg->iob.io->desc->data: NULL;
	if (g) {
		R_LOG_INFO ("bochs attach: ok");
		pd->desc = &g->desc;
		pd->bCapturaRegs = true;
		pd->bStep = false;
		pd->bBreak = false;
	}
	return g != NULL;
}

static bool r_debug_bochs_detach(RDebug *dbg, int pid) {
	PluginData *pd = R_UNWRAP3 (dbg, current, plugin_data);
	if (!pd) {
		return false;
	}
	pd->desc = NULL;
	return true;
}

static char *r_debug_bochs_reg_profile(RDebug *dbg) {
	int bits = dbg->anal->config->bits;

	if (bits == 16 || bits == 32 || bits == 64) {
		return strdup (
				"=PC	csip\n"
				"=SP	rsp\n"
				"=BP	rbp\n"
				"=A0	rax\n"
				"=A1	rbx\n"
				"=A2	rcx\n"
				"=A3	rdi\n"

				"seg	es	2	0x038	0	\n"
				"seg	cs	2	0x03A	0	\n"
				"seg	ss	2	0x03C	0	\n"
				"seg	ds	2	0x03E	0	\n"
				"seg	fs	2	0x040	0	\n"
				"seg	gs	2	0x042	0	\n"

				"gpr	riz	8	?	0	\n"
				"gpr	rax	8	0x078	0	\n"
				"gpr	eax	4	0x078	0	\n"
				"gpr	ax	2	0x078	0	\n"
				"gpr	al	1	0x078	0	\n"
				"gpr	rcx	8	0x080	0	\n"
				"gpr	ecx	4	0x080	0	\n"
				"gpr	cx	2	0x080	0	\n"
				"gpr	cl	1	0x078	0	\n"
				"gpr	rdx	8	0x088	0	\n"
				"gpr	edx	4	0x088	0	\n"
				"gpr	dx	2	0x088	0	\n"
				"gpr	dl	1	0x088	0	\n"
				"gpr	rbx	8	0x090	0	\n"
				"gpr	ebx	4	0x090	0	\n"
				"gpr	bx	2	0x090	0	\n"
				"gpr	bl	1	0x090	0	\n"
				"gpr	rsp	8	0x098	0	\n"
				"gpr	esp	4	0x098	0	\n"
				"gpr	sp	2	0x098	0	\n"
				"gpr	spl	1	0x098	0	\n"
				"gpr	rbp	8	0x0A0	0	\n"
				"gpr	ebp	4	0x0A0	0	\n"
				"gpr	bp	2	0x0A0	0	\n"
				"gpr	bpl	1	0x0A0	0	\n"
				"gpr	rsi	8	0x0A8	0	\n"
				"gpr	esi	4	0x0A8	0	\n"
				"gpr	si	2	0x0A8	0	\n"
				"gpr	sil	1	0x0A8	0	\n"
				"gpr	rdi	8	0x0B0	0	\n"
				"gpr	edi	4	0x0B0	0	\n"
				"gpr	di	2	0x0B0	0	\n"
				"gpr	dil	1	0x0B0	0	\n"
				"gpr	r8	8	0x0B8	0	\n"
				"gpr	r8d	4	0x0B8	0	\n"
				"gpr	r8w	2	0x0B8	0	\n"
				"gpr	r8b	1	0x0B8	0	\n"
				"gpr	r9	8	0x0C0	0	\n"
				"gpr	r9d	4	0x0C0	0	\n"
				"gpr	r9w	2	0x0C0	0	\n"
				"gpr	r9b	1	0x0C0	0	\n"
				"gpr	r10	8	0x0C8	0	\n"
				"gpr	r10d	4	0x0C8	0	\n"
				"gpr	r10w	2	0x0C8	0	\n"
				"gpr	r10b	1	0x0C8	0	\n"
				"gpr	r11	8	0x0D0	0	\n"
				"gpr	r11d	4	0x0D0	0	\n"
				"gpr	r11w	2	0x0D0	0	\n"
				"gpr	r11b	1	0x0D0	0	\n"
				"gpr	r12	8	0x0D8	0	\n"
				"gpr	r12d	4	0x0D8	0	\n"
				"gpr	r12w	2	0x0D8	0	\n"
				"gpr	r12b	1	0x0D8	0	\n"
				"gpr	r13	8	0x0E0	0	\n"
				"gpr	r13d	4	0x0E0	0	\n"
				"gpr	r13w	2	0x0E0	0	\n"
				"gpr	r13b	1	0x0E0	0	\n"
				"gpr	r14	8	0x0E8	0	\n"
				"gpr	r14d	4	0x0E8	0	\n"
				"gpr	r14w	2	0x0E8	0	\n"
				"gpr	r14b	1	0x0E8	0	\n"
				"gpr	r15	8	0x0F0	0	\n"
				"gpr	r15d	4	0x0F0	0	\n"
				"gpr	r15w	2	0x0F0	0	\n"
				"gpr	r15b	1	0x0F0	0	\n"
				"gpr	rip	8	0x0F8	0	\n"
				"gpr	eip	4	0x0F8	0	\n"
				"gpr	csip	8	0x000	0	\n"
				);
	}
	return NULL;
}

static bool init_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	R_RETURN_VAL_IF_FAIL (dbg && ds, false);
	PluginData *pd = R_NEW0 (PluginData);
	pd->bCapturaRegs = true;
	pd->bAjusta = true;
	ds->plugin_data = pd;
	return true;
}

static bool fini_plugin(RDebug *dbg, RDebugPluginSession *ds) {
	R_RETURN_VAL_IF_FAIL (dbg && ds, false);
	// desc is owned by the io plugin
	R_FREE (ds->plugin_data);
	return true;
}

RDebugPlugin r_debug_plugin_bochs = {
	.meta = {
		.name = "bochs",
		.author = "SkUaTeR",
		.desc = "bochs debug plugin",
		.license = "LGPL-3.0-only",
	},
	.arch = "x86",
	.bits = R_SYS_BITS_PACK3 (16, 32, 64),
	.init_plugin = init_plugin,
	.fini_plugin = fini_plugin,
	.step = r_debug_bochs_step,
	.cont = r_debug_bochs_continue,
	.attach = r_debug_bochs_attach,
	.detach = r_debug_bochs_detach,
	.canstep = 1,
	.stop = r_debug_bochs_stop,
	.wait = r_debug_bochs_wait,
	.map_get = r_debug_bochs_map_get,
	.breakpoint = r_debug_bochs_breakpoint,
	.reg_read = bochs_reg_read,
	.reg_write = bochs_reg_write,
	.reg_profile = r_debug_bochs_reg_profile,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_DBG,
	.data = &r_debug_plugin_bochs,
	.version = R2_VERSION
};
#endif
