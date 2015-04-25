#include <proc.h>
#include <slab.h>
#include <string.h>
#include <sync.h>
#include <pmm.h>
#include <error.h>
#include <sched.h>
#include <elf.h>
#include <vmm.h>
#include <trap.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <swap.h>
#include <fs.h>

void forkrets(struct trapframe *tf);

// alloc_proc - create a proc struct and init fields
struct proc_struct *alloc_proc(void)
{
	struct proc_struct *proc = kmalloc(sizeof(struct proc_struct));
	if (proc != NULL) {
		proc->state = PROC_UNINIT;
		proc->pid = -1;
		proc->runs = 0;
		proc->kstack = 0;
		proc->need_resched = 0;
		proc->parent = NULL;
		proc->mm = NULL;
		memset(&(proc->context), 0, sizeof(struct context));
		proc->tf = NULL;
		proc->cr3 = boot_cr3;
		proc->flags = 0;
		memset(proc->name, 0, PROC_NAME_LEN);
		proc->wait_state = 0;
		proc->cptr = proc->optr = proc->yptr = NULL;
		list_init(&(proc->thread_group));
		proc->rq = NULL;
		list_init(&(proc->run_link));
		proc->time_slice = 0;
		proc->sem_queue = NULL;
		event_box_init(&(proc->event_box));
		proc->fs_struct = NULL;
	}
	return proc;
}

// forkret -- the first kernel entry point of a new thread/process
// NOTE: the addr of forkret is setted in copy_thread function
//       after switch_to, the current proc will execute here.
static void forkret(void)
{
	forkrets(current->tf);
}

// kernel_thread - create a kernel thread using "fn" function
// NOTE: the contents of temp trapframe tf will be copied to 
//       proc->tf in do_fork-->copy_thread function
int kernel_thread(int (*fn) (void *), void *arg, uint32_t clone_flags)
{
	struct trapframe tf;
	memset(&tf, 0, sizeof(struct trapframe));
	tf.tf_cs = KERNEL_CS;
	tf.tf_ds = tf.tf_es = tf.tf_ss = KERNEL_DS;
	tf.tf_regs.reg_ebx = (uint32_t) fn;
	tf.tf_regs.reg_edx = (uint32_t) arg;
	tf.tf_eip = (uint32_t) kernel_thread_entry;
	return do_fork(clone_flags | CLONE_VM, 0, &tf);
}

int ucore_kernel_thread(int (*fn) (void *), void *arg, uint32_t clone_flags)
{
	kernel_thread(fn, arg, clone_flags);
}

void de_thread_arch_hook(struct proc_struct *proc)
{
}

// copy_thread - setup the trapframe on the  process's kernel stack top and
//             - setup the kernel entry point and stack of process
int
copy_thread(uint32_t clone_flags, struct proc_struct *proc,
	    uintptr_t esp, struct trapframe *tf)
{
	proc->tf = (struct trapframe *)(proc->kstack + KSTACKSIZE) - 1;
	*(proc->tf) = *tf;
	proc->tf->tf_regs.reg_eax = 0;
	proc->tf->tf_esp = esp;
	proc->tf->tf_eflags |= FL_IF;

	proc->context.eip = (uintptr_t) forkret;
	proc->context.esp = (uintptr_t) (proc->tf);

	return 0;
}

//Lab9 YOUR CODE: fullfill the stack for the dynamic linker
<<<<<<< HEAD

//use arch prefix, please.
void arch_setup_user_proc_trapframe(struct trapframe* tf, uintptr_t stacktop,
		uintptr_t entry) {
=======
#define DYLIB_DEBUG;
int arch_init_new_process_context(
		struct proc_struct *proc,
		struct elfhdr *elf,
		uint32_t argc,	//uint32_t, actually.
		char **kargv,
		uint32_t envc,	//uint32_t, actually.
		char **kenvv,
		uint32_t is_dynamic,
		uintptr_t ldso_entry,
		uintptr_t load_address,
		uintptr_t ldso_base) {

#ifdef DYLIB_DEBUG
		//I have to check the assumption when debugging, since nobody did it.
		assert(elf->e_phentsize == sizeof(struct proghdr));
#endif

	if (elf->e_phentsize != sizeof(struct proghdr)) {
		return -1;	//Incompatible elf.
	}
	if (argc + envc >= USTACKPAGE / 2) {
		return -1;	//Too many arguments.
	}

	uintptr_t envbase = USTACKTOP - envc * PGSIZE, argbase = envbase - argc * PGSIZE;
	uintptr_t argvbase, envvbase;
	if (is_dynamic) {
		size_t aux[] = { //32bit on i386, 64bit on x86_64. I haven't check other platforms.
				ELF_AT_BASE,
				ldso_base,
				ELF_AT_PHDR,
				load_address + elf->e_phoff,
				ELF_AT_PHNUM,
				elf->e_phnum,
				ELF_AT_PHENT,
				elf->e_phentsize,
				ELF_AT_PAGESZ,
				PGSIZE,
				ELF_AT_ENTRY,
				elf->e_entry,
				ELF_AT_NULL,
		};
		uintptr_t auxbase = argbase - sizeof(aux);
		memcpy(auxbase, aux, sizeof(aux));
		envvbase = auxbase - (envc + 1) * sizeof(char*);
		argvbase = envvbase - (argc + 1) * sizeof(char*);
	} else {
		envvbase = argbase - (envc + 1) * sizeof(char*);
		argvbase = envvbase - (argc + 1) * sizeof(char*);
	}
	//setup args
	uint32_t iter;
	for (iter = 0; iter < argc; iter ++) {
		((char**)argvbase)[iter] = strncpy(argbase + iter * PGSIZE, kargv[iter], PGSIZE - 1);
	}
	for (iter = 0; iter < envc; iter ++) {
		((char**)envvbase)[iter] = strncpy(envbase + iter * PGSIZE, kenvv[iter], PGSIZE - 1);
	}
	uintptr_t pargc = argvbase - sizeof(uint32_t);
	*(uint32_t*)pargc = argc;
	arch_setup_user_proc_trapframe(proc->tf, pargc, is_dynamic ? ldso_entry : elf->e_entry);
	return 0;
}
#ifdef DYLIB_DEBUG
#undef DYLIB_DEBUG
#endif

void arch_setup_user_proc_trapframe(struct trapframe* tf, uintptr_t stacktop, uintptr_t entry) {
>>>>>>> parent of d161027... I am under the hill of syscall
	memset(tf, 0, sizeof(struct trapframe));
	tf->tf_cs = USER_CS;
	tf->tf_ds = USER_DS;
	tf->tf_es = USER_DS;
	tf->tf_ss = USER_DS;
	tf->tf_esp = stacktop;
	tf->tf_eip = entry;
	tf->tf_eflags = FL_IF;
}

//end




int
init_new_context(struct proc_struct *proc, struct elfhdr *elf,
		 int argc, char **kargv, int envc, char **kenvp)
{
	uintptr_t stacktop = USTACKTOP - argc * PGSIZE;
	char **uargv = (char **)(stacktop - argc * sizeof(char *));
	int i;
	for (i = 0; i < argc; i++) {
		uargv[i] = strcpy((char *)(stacktop + i * PGSIZE), kargv[i]);
	}
	stacktop = (uintptr_t) uargv - sizeof(int);
	*(int *)stacktop = argc;

	struct trapframe *tf = proc->tf;
	memset(tf, 0, sizeof(struct trapframe));
	tf->tf_cs = USER_CS;
	tf->tf_ds = USER_DS;
	tf->tf_es = USER_DS;
	tf->tf_ss = USER_DS;
	tf->tf_esp = stacktop;
	tf->tf_eip = elf->e_entry;
	tf->tf_eflags = FL_IF;

	return 0;
}

int do_execve_arch_hook(int argc, char **kargv)
{
	return 0;
}

// kernel_execve - do SYS_exec syscall to exec a user program called by user_main kernel_thread
int kernel_execve(const char *name, const char **argv, const char **kenvp)
{
	int ret;
	asm volatile ("int %1;":"=a" (ret)
		      :"i"(T_SYSCALL), "0"(SYS_exec), "d"(name), "c"(argv),
		      "b"(kenvp)
		      :"memory");
	return ret;
}

// cpu_idle - at the end of kern_init, the first kernel thread idleproc will do below works
void cpu_idle(void)
{
	while (1) {
		if (current->need_resched) {
			schedule();
		}
	}
}
