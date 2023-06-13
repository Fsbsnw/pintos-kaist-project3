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
#include "threads/palloc.h"

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
	if(addr == NULL) exit(-1);
	if(!is_user_vaddr(addr)) exit(-1);
  if (pml4_get_page(thread_current()->pml4, addr) == NULL) exit(-1);
}

struct list_elem *
find_fd_in_fdt(struct thread * cur, int fd)
{
	struct list_elem * e;
	struct file_descriptor * file_des; 
	for (e = list_begin(&cur->fdt); e != list_end(&cur->fdt); e = list_next(e))
	{
		file_des = list_entry(e, struct file_descriptor, elem);
		if(file_des->fd == fd) return e;
	}
	return NULL;
}


// 0.
void halt(void){
	power_off();
}

// 1.
void exit(int status)
{
    struct thread *curr = thread_current();
    curr->exit_status = status;
    printf("%s: exit(%d)\n", curr->name, status);
    thread_exit();
}

// 2.
int fork(const char *thread_name, struct intr_frame *f)
{
    return process_fork(thread_name,f);
}

// 3.
int exec(const char *cmd_line)
{

	check_address(cmd_line);
	char * cmd_line_copy;
	cmd_line_copy = palloc_get_page(0);
	if (cmd_line_copy == NULL)
			exit(-1);
	strlcpy(cmd_line_copy, cmd_line, PGSIZE);

	// 스레드의 이름을 변경하지 않고 바로 실행한다.
	if (process_exec(cmd_line_copy) == -1)
			exit(-1); // 실패 시 status -1로 종료한다.
}

// 4.
int wait(int pid)
{
    return process_wait(pid);
}

// 5.
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
	struct thread * cur = thread_current();

	if(cur->next_fd > 128) return -1;
	if(*file == NULL) return -1;

	struct file * fp = filesys_open(file);
	if(fp == NULL) return -1;

	struct file_descriptor * new_fd = malloc(sizeof(struct file_descriptor));
	cur->next_fd++;
	new_fd->fd = cur->next_fd;
	new_fd->file = fp;

	list_push_back(&cur->fdt, &new_fd->elem);

	return new_fd->fd;
}

// 8.
int filesize(int fd) {

	struct thread * cur = thread_current();
	struct list_elem * e = find_fd_in_fdt(cur,fd);
	if(e == NULL) return -1;

	struct file_descriptor * file_des = list_entry(e,struct file_descriptor, elem);

	if(file_des->file == NULL) exit(-1);

	return file_length(file_des->file);
}

// 9.
int read(int fd, void *buffer, unsigned size) {
	// 유효한 주소인지부터 체크
	unsigned char *buf = buffer;
	check_address(buffer);

	/* STDOUT일 때: -1 반환 */
	if (fd == 1) return -1;

	/* STDIN일 때: */
	if (fd == 0) return input_getc();

	struct thread *cur = thread_current();
	off_t buff_size;
	struct list_elem * e = find_fd_in_fdt(cur,fd);
	if(e == NULL) return -1;

	struct file_descriptor * file_des = list_entry(e,struct file_descriptor, elem);
	if(file_des->file == NULL) return -1;

	lock_acquire(&filesys_lock);
	buff_size = file_read(file_des->file, buffer, size);
	lock_release(&filesys_lock);

	return buff_size;
}



// 10.
int write (int fd, const void *buffer, unsigned size) {
	check_address(buffer);
	// check_address(buffer + size);

	if(fd <= 0) return -1;

	if (fd == 1) {
		putbuf(buffer, size);
		return size;
	}

	struct thread *cur = thread_current();
	struct list_elem * e = find_fd_in_fdt(cur,fd);
	
	if(e == NULL) return -1;

	struct file_descriptor * file_des = list_entry(e,struct file_descriptor, elem);
	if(file_des->file == NULL) return -1;

	lock_acquire(&filesys_lock);
	off_t write_size = file_write(file_des->file, buffer, size);
	lock_release(&filesys_lock);
	
	return write_size;
}
// 11.
void seek(int fd, unsigned position)
{
	struct thread *cur = thread_current();
	struct list_elem * e = find_fd_in_fdt(cur,fd);
	
	if(e == NULL) return;

	struct file_descriptor * file_des = list_entry(e,struct file_descriptor, elem);
	if(file_des->file == NULL) return;

	file_seek(file_des->file, position);
}
// 12.
unsigned tell(int fd)
{

	struct thread *cur = thread_current();
	struct list_elem * e = find_fd_in_fdt(cur,fd);
	
	if(e == NULL) return;

	struct file_descriptor * file_des = list_entry(e,struct file_descriptor, elem);
	if(file_des->file == NULL) return;
  return file_tell(file_des->file);
}

// 13.
void close(int fd)
{
	struct thread *cur = thread_current();
	struct list_elem * e = find_fd_in_fdt(cur,fd);
	
	if(e == NULL) return;

	struct file_descriptor * file_des = list_entry(e,struct file_descriptor, elem);
	if(file_des->file == NULL) return;

	file_close(file_des->file);
	list_remove(&file_des->elem);
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
syscall_handler (struct intr_frame *f) {
	int sys_number = f->R.rax; // rax: 시스템 콜 넘버
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
		case SYS_FORK:
			f->R.rax = fork(f->R.rdi, f);
			break;		
		case SYS_EXEC:
			f->R.rax = exec(f->R.rdi);
			break;
		case SYS_WAIT:
			f->R.rax = wait(f->R.rdi);
			break;
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
		case SYS_SEEK:
			seek(f->R.rdi, f->R.rsi);
			break;
		case SYS_TELL:
			f->R.rax = tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			close(f->R.rdi);
		default:
			break;
	}
}
