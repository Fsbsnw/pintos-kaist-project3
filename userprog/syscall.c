#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"


/* Project 2 */
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/synch.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

/* Project 2 */
struct lock filesys_lock;

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void check_address(void *addr)
{
    if (addr == NULL)
        exit(-1);
    if (!is_user_vaddr(addr))
        exit(-1);
    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
        exit(-1);
}


// 1.
void halt(void){
	power_off();
}

// 2.
void exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}


bool create(const char *file, unsigned initial_size)
{
    check_address(file);
    return filesys_create(file, initial_size);
}

// 6.
bool remove (const char *file) {
	check_address(file);
	return filesys_remove(file);
}

// 7.
int open (const char *file) {
	check_address(file);
	
	int fd;
	struct thread *cur = thread_current();
	struct file *file_obj = filesys_open(file);
	if(cur->name==NULL || file_obj == NULL) return -1;
	
	for(fd=2;fd<128,cur->fdt[fd]!=NULL;fd++) continue;

	if(fd==128){
		file_close(file_obj);
		fd = -1;
	}
	else{
		cur->fdt[fd] = file_obj;
		cur->fd = fd;
	}

	return fd;
}

// 8.
int filesize(int fd) {

	if(	fd < 0 || fd >= 128) return -1;

	struct thread * cur = thread_current();
	struct file *fileobj = cur->fdt[fd];
	if (fileobj == NULL) return -1;

	return file_length(fileobj);
}

// 9.
int read(int fd, void *buffer, unsigned size) {
	// 유효한 주소인지부터 체크
	unsigned char *buf = buffer;
	int read_count;
	check_address(buffer);
	check_address(buffer + size -1);

	if(	fd < 0 || fd>=128) return -1;
	
	struct thread *cur = thread_current();
	struct file *fileobj = cur->fdt[fd];

	if (fileobj == NULL) return -1;
	
	/* STDIN일 때: */
	if (fd == 0) {
		char key;
		for (read_count = 0; read_count < size; read_count++) {
			key  = input_getc();
			*buf++ = key;
			if (key == '\0') break;
		}
	}
	/* STDOUT일 때: -1 반환 */
	else if (fd == 1) return -1;
	else {
		lock_acquire(&filesys_lock);
		read_count = file_read(fileobj, buffer, size); // 파일 읽어들일 동안만 lock 걸어준다.
		lock_release(&filesys_lock);

	}
	return read_count;
}



// 10.
int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	check_address(buffer + size);

	if(	fd < 0 || fd >= 128) return -1;
	struct thread *cur = thread_current();
	struct file *fileobj = cur->fdt[fd];
	if (fileobj == NULL) return -1;

	int write_count;
	if (fd == 1) {
		putbuf(buffer, size);
		write_count = size;
	}
	else if (fd == 0) return -1;
	else {
		lock_acquire(&filesys_lock);
		write_count = file_write(fileobj, buffer, size);
		lock_release(&filesys_lock);
	}
	return write_count;
}

// 13.
void close(int fd)
{
		if(	fd < 2 || fd >= 128) return;
		struct thread *cur = thread_current();
    struct file *file = cur->fdt[fd];
    if(file == NULL) return;
    file_close(file);
    cur->fdt[fd] = NULL;
}

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
	lock_init(&filesys_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	int sys_number = f->R.rax; // rax: 시스템 콜 넘버
	// printf("sys_number : %d\n",sys_number);
    /* 
	인자 들어오는 순서:
	1번째 인자: %rdi
	2번째 인자: %rsi
	3번째 인자: %rdx
	4번째 인자: %r10
	5번째 인자: %r8
	6번째 인자: %r9 
	*/
	// TODO: Your implementation goes here.
	switch(sys_number) {
		case SYS_HALT:
			halt();
			break;
		case SYS_EXIT:
			exit(f->R.rdi);
			break;
		// case SYS_FORK:
		// 	fork(f->R.rdi);
		// 	break;		
		// case SYS_EXEC:
		// 	exec(f->R.rdi);
		// 	break;
		// case SYS_WAIT:
		// 	wait(f->R.rdi);
		// 	break;
		case SYS_CREATE:
			f->R.rax = create(f->R.rdi, f->R.rsi);
			break;
		case SYS_REMOVE:
			f->R.rax = remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = filesize(f->R.rdi);
			break;
		case SYS_READ:
			f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
			break;
		case SYS_WRITE:
			f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
			break;	
	// 	case SYS_SEEK:
	// 		seek(f->R.rdi, f->R.rsi);		
	// 	case SYS_TELL:
	// 		tell(f->R.rdi);		
		case SYS_CLOSE:
			close(f->R.rdi);
		default:
			break;
	}
	// printf ("system call!\n");
}
