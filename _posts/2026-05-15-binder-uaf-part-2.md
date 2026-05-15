
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

The implementation looks like so:
