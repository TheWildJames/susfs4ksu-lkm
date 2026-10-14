// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_or_entry.c - open_redirect's forward direction, done at the NAME layer.
 *
 * Why this exists: the vfs_open kprobe has to keep a cached struct path per rule, because by the
 * time vfs_open runs the name is already resolved and nothing can sleep there.  Cached dentry and
 * mount references are what stop a filesystem teardown from finishing while a rule points into it.
 * Upstream has no such problem because it patches do_sys_openat2, where it simply builds a new
 * struct filename from the stored string; those symbols are LTO-inlined here and cannot be probed,
 * but the syscall entry can be replaced - susfs_opath.c already replaces exactly the five entries
 * this needs - so the same thing can be done at the same layer as upstream.
 *
 * What it does per matching open, in process context before the syscall runs:
 *   getname_flags() + filename_lookup()  -> which inode is the caller opening (relative paths too)
 *   susfs_open_redirect_match_path()     -> is that the target of a live rule, and where does it go
 *   filp_open()                          -> open the target ourselves
 *   get_unused_fd_flags() + fd_install() -> hand the caller a fd, exactly like the syscall would
 *   and return the fd instead of running the original syscall.
 *
 * Nothing is cached, so a rule holds no reference of any kind: this is what makes open_redirect
 * stop mattering to umount.  All six kernel functions are resolved by name - filp_open,
 * get_unused_fd_flags and fd_install are exported, getname_flags, filename_lookup and putname are
 * not - and the layer stays off if any of them is missing.
 *
 * On by default (module parameter or_entry).  It used to be opt-in, back when the vfs_open probe was
 * still the default forward direction; that probe is gone, so this layer IS the forward direction -
 * which is also why or_register() refuses a rule while it is not armed, and why an unarmed layer
 * says so in the log instead of failing silently.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/fcntl.h>	/* AT_FDCWD, O_CLOEXEC, __O_TMPFILE */
#include <linux/path.h>		/* path_put() */
#include <linux/namei.h>	/* getname_flags/filename_lookup prototypes, LOOKUP_FOLLOW */
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/atomic.h>
#include <linux/limits.h>
#include "susfs.h"
#include "susfs_log.h"
#include "symbol_resolver.h"
#include "susfs_or_entry.h"

/* include/uapi/linux/openat2.h: three u64 fields, identical on both ABIs we build for. */
struct susfs_open_how {
	__u64 flags;
	__u64 mode;
	__u64 resolve;
};

/* Every one of these is resolved by name at load; see the header comment for which are exported. */
static struct filename *(*or_getname_flags_fn)(const char __user *name, int flags, int *empty);
static int (*or_filename_lookup_fn)(int dfd, struct filename *name, unsigned flags,
				    struct path *path, struct path *root);
static void (*or_putname_fn)(struct filename *name);
static struct file *(*or_filp_open_fn)(const char *name, int flags, umode_t mode);
static int (*or_get_unused_fd_flags_fn)(unsigned flags);
static void (*or_fd_install_fn)(unsigned int fd, struct file *file);

static bool or_entry_ready;
static atomic_t or_entry_hits = ATOMIC_INIT(0);

/* On by default: this IS the forward direction now (the vfs_open probe is gone from
 * susfs_open_redirect.c), and the layer reports rather than redirects when a symbol is missing - the
 * rule-management path then refuses rules, so an unarmed layer is loud instead of a silent no-op. */
static bool or_entry_param = true;
module_param_named(or_entry, or_entry_param, bool, 0600);

susfs_or_entry_fn_t susfs_or_entry_hook;

/* The original syscall is not called at all when this redirects, so nothing has to be undone if the
 * process is killed mid-way; the fd is installed last, which is the same order the kernel uses.
 *
 * __nocfi noinline is the §6 rule for every call through a runtime-resolved pointer: without it,
 * CFI instrumentation lands in whichever function this ends up in (the opath wrapper), and a
 * checked indirect call into the kernel is a panic rather than an error return.  This is also why
 * every kernel function above is held in a plain pointer and called from here, never from the
 * wrapper itself. */
static __nocfi noinline long or_entry_redirect(const struct pt_regs *regs, int kind)
{
	const char __user *uname = NULL;
	unsigned long flags = 0, mode = 0;
	struct susfs_open_how how;
	struct filename *name;
	struct path path;
	const char *target;
	struct file *f;
	int dfd = AT_FDCWD;
	long res;
	int fd;

	if (!or_entry_ready || !READ_ONCE(or_entry_param))
		return SUSFS_OR_ENTRY_PASS;

	/* This hook is reached for every open() on the system, so the empty case has to be one load: no
	 * rules means nothing to resolve a name for.  (A rule that was deleted still counts - slots are
	 * never reused - which only means the lookup below runs and misses.) */
	if (!susfs_open_redirect_active())
		return SUSFS_OR_ENTRY_PASS;

	/* arm64 keeps a syscall's arguments in regs[0..5] for native and compat alike, so the
	 * argument number IS the register index (arch/arm64/include/asm/syscall_wrapper.h). */
	switch (kind) {
	case SUSFS_OR_ENTRY_OPENAT:
	case SUSFS_OR_ENTRY_COMPAT_OPENAT:
		dfd = (int)regs->regs[0];
		uname = (const char __user *)regs->regs[1];
		flags = regs->regs[2];
		mode = regs->regs[3];
		break;
	case SUSFS_OR_ENTRY_COMPAT_OPEN:
		/* COMPAT_SYSCALL_DEFINE3: no dirfd, so the arguments shift down by one. */
		uname = (const char __user *)regs->regs[0];
		flags = regs->regs[1];
		mode = regs->regs[2];
		break;
	case SUSFS_OR_ENTRY_OPENAT2:
	case SUSFS_OR_ENTRY_COMPAT_OPENAT2:
		dfd = (int)regs->regs[0];
		uname = (const char __user *)regs->regs[1];
		if (copy_from_user(&how, (const void __user *)regs->regs[2], sizeof(how)))
			return SUSFS_OR_ENTRY_PASS;
		flags = how.flags;
		mode = how.mode;
		break;
	default:
		return SUSFS_OR_ENTRY_PASS;
	}

	/* O_TMPFILE is not a path open in the sense filp_open() models (it needs the O_DIRECTORY
	 * part handled by the caller's dirfd), so those are left to the kernel untouched. */
	if (flags & __O_TMPFILE)
		return SUSFS_OR_ENTRY_PASS;

	/* Which inode is the caller opening?  Lookup follows symlinks because that is what the
	 * caller's own open will end up doing; a path that does not resolve yet (O_CREAT of a new
	 * file) cannot be the target of a rule, so the kernel is left to answer it. */
	name = or_getname_flags_fn(uname, 0, NULL);
	if (IS_ERR(name))
		return SUSFS_OR_ENTRY_PASS;
	res = or_filename_lookup_fn(dfd, name, LOOKUP_FOLLOW, &path, NULL);
	or_putname_fn(name);
	if (res)
		return SUSFS_OR_ENTRY_PASS;

	target = susfs_open_redirect_match_path(&path);
	path_put(&path);	/* no reference is kept anywhere: the rule owns none either */
	if (!target)
		return SUSFS_OR_ENTRY_PASS;

	/* CLOEXEC is the fd table's business, not the open's: build_open_flags() rejects it. */
	f = or_filp_open_fn(target, (int)(flags & ~O_CLOEXEC), (umode_t)mode);
	if (IS_ERR(f))
		return PTR_ERR(f);

	fd = or_get_unused_fd_flags_fn((unsigned)(flags & O_CLOEXEC));
	if (fd < 0) {
		fput(f);
		return fd;
	}
	or_fd_install_fn((unsigned)fd, f);

	atomic_inc(&or_entry_hits);
	return fd;
}

int susfs_or_entry_init(void)
{
	or_getname_flags_fn = (void *)find_kernel_symbol_exact("getname_flags");
	or_filename_lookup_fn = (void *)find_kernel_symbol_exact("filename_lookup");
	or_putname_fn = (void *)find_kernel_symbol_exact("putname");
	or_filp_open_fn = (void *)find_kernel_symbol_exact("filp_open");
	or_get_unused_fd_flags_fn = (void *)find_kernel_symbol_exact("get_unused_fd_flags");
	or_fd_install_fn = (void *)find_kernel_symbol_exact("fd_install");

	if (!or_getname_flags_fn || !or_filename_lookup_fn || !or_putname_fn ||
	    !or_filp_open_fn || !or_get_unused_fd_flags_fn || !or_fd_install_fn) {
		SUSFS_LOGI("or_entry: not armed, a symbol is missing (getname_flags=%d filename_lookup=%d putname=%d filp_open=%d get_unused_fd_flags=%d fd_install=%d) - open_redirect will refuse rules\n",
			   !!or_getname_flags_fn, !!or_filename_lookup_fn, !!or_putname_fn,
			   !!or_filp_open_fn, !!or_get_unused_fd_flags_fn, !!or_fd_install_fn);
		return 0;
	}

	or_entry_ready = true;
	smp_wmb();
	WRITE_ONCE(susfs_or_entry_hook, or_entry_redirect);
	SUSFS_LOGI("or_entry: name-layer redirection %s (or_entry=%d); open_redirect rules hold no inode while it is on\n",
		   or_entry_param ? "armed" : "ready but off", (int)or_entry_param);
	return 0;
}

void susfs_or_entry_exit(void)
{
	WRITE_ONCE(susfs_or_entry_hook, NULL);
	smp_mb();
	or_entry_ready = false;
}
