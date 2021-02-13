/***************************************************************************
 * ncat_exec_win.c -- Windows-specific subprocess execution.               *
 ***********************IMPORTANT NMAP LICENSE TERMS************************
 *                                                                         *
 * The Nmap Security Scanner is (C) 1996-2020 Insecure.Com LLC ("The Nmap  *
 * Project"). Nmap is also a registered trademark of the Nmap Project.     *
 *                                                                         *
 * This program is distributed under the terms of the Nmap Public Source   *
 * License (NPSL). The exact license text applying to a particular Nmap    *
 * release or source code control revision is contained in the LICENSE     *
 * file distributed with that version of Nmap or source code control       *
 * revision. More Nmap copyright/legal information is available from       *
 * https://nmap.org/book/man-legal.html, and further information on the    *
 * NPSL license itself can be found at https://nmap.org/npsl. This header  *
 * summarizes some key points from the Nmap license, but is no substitute  *
 * for the actual license text.                                            *
 *                                                                         *
 * Nmap is generally free for end users to download and use themselves,    *
 * including commercial use. It is available from https://nmap.org.        *
 *                                                                         *
 * The Nmap license generally prohibits companies from using and           *
 * redistributing Nmap in commercial products, but we sell a special Nmap  *
 * OEM Edition with a more permissive license and special features for     *
 * this purpose. See https://nmap.org/oem                                  *
 *                                                                         *
 * If you have received a written Nmap license agreement or contract       *
 * stating terms other than these (such as an Nmap OEM license), you may   *
 * choose to use and redistribute Nmap under those terms instead.          *
 *                                                                         *
 * The official Nmap Windows builds include the Npcap software             *
 * (https://npcap.org) for packet capture and transmission. It is under    *
 * separate license terms which forbid redistribution without special      *
 * permission. So the official Nmap Windows builds may not be              *
 * redistributed without special permission (such as an Nmap OEM           *
 * license).                                                               *
 *                                                                         *
 * Source is provided to this software because we believe users have a     *
 * right to know exactly what a program is going to do before they run it. *
 * This also allows you to audit the software for security holes.          *
 *                                                                         *
 * Source code also allows you to port Nmap to new platforms, fix bugs,    *
 * and add new features.  You are highly encouraged to submit your         *
 * changes as a Github PR or by email to the dev@nmap.org mailing list     *
 * for possible incorporation into the main distribution. Unless you       *
 * specify otherwise, it is understood that you are offering us very       *
 * broad rights to use your submissions as described in the Nmap Public    *
 * Source License Contributor Agreement. This is important because we      *
 * fund the project by selling licenses with various terms, and also       *
 * because the inability to relicense code has caused devastating          *
 * problems for other Free Software projects (such as KDE and NASM).       *
 *                                                                         *
 * The free version of Nmap is distributed in the hope that it will be     *
 * useful, but WITHOUT ANY WARRANTY; without even the implied warranty of  *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. Warranties,        *
 * indemnification and commercial support are all available through the    *
 * Npcap OEM program--see https://nmap.org/oem.                            *
 *                                                                         *
 ***************************************************************************/

 /* $Id$ */

#include "ncat.h"
#include "ws2tcpip.h"

/* This structure holds information about a subprocess with redirected input
   and output handles. */
struct subprocess_info {
    HANDLE proc;
    struct fdinfo fdn;
    HANDLE child_in_r;
    HANDLE child_in_w;
    HANDLE child_out_r;
    HANDLE child_out_w;
};

#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#define socklen_t int
/* A list of subprocesses, so we can kill them when the program exits. */
static HANDLE subprocesses[1024];
static int subprocess_max_index = 0;
/* Prevent concurrent access to the subprocesses table by the main process and
   a thread. Protects subprocesses and subprocesses_max_index. */
static HANDLE subprocesses_mutex = NULL;

static int start_subprocess(char* cmdexec, struct subprocess_info* info);
static DWORD WINAPI subprocess_thread_func(void* data);

static int register_subprocess(HANDLE proc);
static int unregister_subprocess(HANDLE proc);
static int get_subprocess_slot(void);

/* Have we registered the termination handler yet? */
static int atexit_registered = 0;
static void terminate_subprocesses(void);
static void sigint_handler(int s);

/* This may be set with set_pseudo_sigchld_handler. It is called when a thread
   representing a child process ends. */
static void (*pseudo_sigchld_handler)(void) = NULL;
/* Simulates blocking of SIGCHLD while the handler runs. Also prevents
   concurrent modification of pseudo_sigchld_handler. */
static HANDLE pseudo_sigchld_mutex = NULL;

int setenv_portable(const char* name, const char* value)
{
    char* var;
    int ret;
    size_t len;
    len = strlen(name) + strlen(value) + 2; /* 1 for '\0', 1 for =. */
    var = (char*)malloc(len);
    snprintf(var, len, "%s=%s", name, value);
    /* _putenv was chosen over SetEnvironmentVariable because variables set
       with the latter seem to be invisible to getenv() calls and Lua uses
       these in the 'os' module. */
    ret = _putenv(var) == 0;
    free(var);
    return ret;
}

void setup_environment(struct fdinfo* info)
{
    union sockaddr_u su;
    char ip[INET6_ADDRSTRLEN];
    char port[16];
    socklen_t alen = sizeof(su);

    if (getpeername(info->fd, &su.sockaddr, &alen) != 0) {
        //bye("getpeername failed: %s", socket_strerror(socket_errno()));
    }
#ifdef HAVE_SYS_UN_H
    if (su.sockaddr.sa_family == AF_UNIX) {
        /* say localhost to keep it backwards compatible */
        setenv_portable("NCAT_REMOTE_ADDR", "localhost");
        setenv_portable("NCAT_REMOTE_PORT", "");
    }
    else
#endif
#ifdef HAVE_LINUX_VM_SOCKETS_H
        if (su.sockaddr.sa_family == AF_VSOCK) {
            char char_u32[11];

            snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_cid);
            setenv_portable("NCAT_REMOTE_ADDR", char_u32);

            snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_port);
            setenv_portable("NCAT_REMOTE_PORT", char_u32);
        }
        else
#endif
            if (getnameinfo((struct sockaddr*)&su, alen, ip, sizeof(ip),
                port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                setenv_portable("NCAT_REMOTE_ADDR", ip);
                setenv_portable("NCAT_REMOTE_PORT", port);
            }
            else {
                //bye("getnameinfo failed: %s", socket_strerror(socket_errno()));
            }

    if (getsockname(info->fd, (struct sockaddr*)&su, &alen) < 0) {
        //bye("getsockname failed: %s", socket_strerror(socket_errno()));
    }
#ifdef HAVE_SYS_UN_H
    if (su.sockaddr.sa_family == AF_UNIX) {
        /* say localhost to keep it backwards compatible, else su.un.sun_path */
        setenv_portable("NCAT_LOCAL_ADDR", "localhost");
        setenv_portable("NCAT_LOCAL_PORT", "");
    }
    else
#endif
#ifdef HAVE_LINUX_VM_SOCKETS_H
        if (su.sockaddr.sa_family == AF_VSOCK) {
            char char_u32[11];

            snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_cid);
            setenv_portable("NCAT_LOCAL_ADDR", char_u32);

            snprintf(char_u32, sizeof(char_u32), "%u", su.vm.svm_port);
            setenv_portable("NCAT_LOCAL_PORT", char_u32);
        }
        else
#endif
            if (getnameinfo((struct sockaddr*)&su, alen, ip, sizeof(ip),
                port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
                setenv_portable("NCAT_LOCAL_ADDR", ip);
                setenv_portable("NCAT_LOCAL_PORT", port);
            }
            else {
                //bye("getnameinfo failed: %s", socket_strerror(socket_errno()));
            }
    setenv_portable("NCAT_PROTO", "TCP");
    //switch (o.proto) {
    //case IPPROTO_TCP:
    //    setenv_portable("NCAT_PROTO", "TCP");
    //    break;
    //case IPPROTO_SCTP:
    //    setenv_portable("NCAT_PROTO", "SCTP");
    //    break;
    //case IPPROTO_UDP:
    //    setenv_portable("NCAT_PROTO", "UDP");
    //    break;
    //}
}


/* Run a child process, redirecting its standard file handles to a socket
   descriptor. Return the child's PID or -1 on error. */
int netrun(struct fdinfo* fdn, char* cmdexec)
{
    struct subprocess_info* info;
    HANDLE thread;
    int pid;

    info = (struct subprocess_info*)malloc(sizeof(*info));
    info->fdn = *fdn;

    pid = start_subprocess(cmdexec, info);
    if (pid == -1) {
        //close(info->fdn.fd);
        free(info);
        return -1;
    }

    /* Start up the thread to handle process I/O. */
    thread = CreateThread(NULL, 0, subprocess_thread_func, info, 0, NULL);
    if (thread == NULL) {
        ////if (o.verbose)
            //logdebug("Error in CreateThread: %d\n", GetLastError());
        free(info);
        return -1;
    }
    CloseHandle(thread);

    return pid;
}

/* Run the given command line as if by exec. Doesn't return. */
void netexec(struct fdinfo* fdn, char* cmdexec)
{
    struct subprocess_info* info;
    int pid;
    DWORD ret;

    info = (struct subprocess_info*)malloc(sizeof(*info));
    info->fdn = *fdn;

    pid = start_subprocess(cmdexec, info);
    if (pid == -1)
        ExitProcess(2);

    /* Run the subprocess thread function, but don't put it in a thread. Just
       run it and exit with its return value because we're simulating exec. */
    ExitProcess(subprocess_thread_func(info));
}

/* Set a pseudo-signal handler that is called when a thread representing a
   child process dies. This is only used on Windows. */
extern void set_pseudo_sigchld_handler(void (*handler)(void))
{
    DWORD rc;

    if (pseudo_sigchld_mutex == NULL) {
        pseudo_sigchld_mutex = CreateMutex(NULL, FALSE, NULL);
        //ncat_assert(pseudo_sigchld_mutex != NULL);
    }
    rc = WaitForSingleObject(pseudo_sigchld_mutex, INFINITE);
    //ncat_assert(rc == WAIT_OBJECT_0);
    pseudo_sigchld_handler = handler;
    rc = ReleaseMutex(pseudo_sigchld_mutex);
    //ncat_assert(rc != 0);
}



/* Run a command and redirect its input and output handles to a pair of
   anonymous pipes.  The process handle and pipe handles are returned in the
   info struct. Returns the PID of the new process, or -1 on error. */
static int run_command_redirected(char* cmdexec, struct subprocess_info* info)
{
    /* Each named pipe we create has to have a unique name. */
    static int pipe_serial_no = 0;
    char pipe_name[32];
    SECURITY_ATTRIBUTES sa;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    setup_environment(&info->fdn);

    /* Make the pipe handles inheritable. */
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    /* The child's input pipe is an ordinary blocking pipe. */
    if (CreatePipe(&info->child_in_r, &info->child_in_w, &sa, 0) == 0) {
        //if (o.verbose)
            //logdebug("Error in CreatePipe: %d\n", GetLastError());
        return -1;
    }

    /* Pipe names must have this special form. */
    snprintf(pipe_name, sizeof(pipe_name), "\\\\.\\pipe\\ncat-%d-%d",
        GetCurrentProcessId(), pipe_serial_no);
   // if (o.debug > 1)
        //logdebug("Creating named pipe \"%s\"\n", pipe_name);

    /* The output pipe has to be nonblocking, which requires this complicated
       setup. */
    info->child_out_r = CreateNamedPipe(pipe_name,
        PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED,
        PIPE_TYPE_BYTE, 1, 4096, 4096, 1000, &sa);
    if (info->child_out_r == 0) {
        //if (o.verbose)
            //logdebug("Error in CreateNamedPipe: %d\n", GetLastError());
        CloseHandle(info->child_in_r);
        CloseHandle(info->child_in_w);
        return -1;
    }
    info->child_out_w = CreateFile(pipe_name,
        GENERIC_WRITE, 0, &sa, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);
    if (info->child_out_w == 0) {
        CloseHandle(info->child_in_r);
        CloseHandle(info->child_in_w);
        CloseHandle(info->child_out_r);
        return -1;
    }
    pipe_serial_no++;

    /* Don't inherit our end of the pipes. */
    SetHandleInformation(info->child_in_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(info->child_out_r, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = info->child_in_r;
    si.hStdOutput = info->child_out_w;
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    memset(&pi, 0, sizeof(pi));

    if (CreateProcess(NULL, cmdexec, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi) == 0) {
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            GetLastError(),
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR)&lpMsgBuf,
            0, NULL);
        CloseHandle(info->child_in_r);
        CloseHandle(info->child_in_w);
        CloseHandle(info->child_out_r);
        CloseHandle(info->child_out_w);
        return -1;
    }

    /* Close hThread here because we have no use for it. hProcess is closed in
       subprocess_info_close. */
    CloseHandle(pi.hThread);

    info->proc = pi.hProcess;

    return pi.dwProcessId;
}

static const char* get_shell(void)
{
    const char* comspec;

    comspec = getenv("COMSPEC");
    if (comspec == NULL)
        comspec = "cmd.exe";

    return comspec;
}

static void subprocess_info_close(struct subprocess_info* info)
{
    closesocket(info->fdn.fd);
    CloseHandle(info->proc);
    CloseHandle(info->child_in_r);
    CloseHandle(info->child_in_w);
    CloseHandle(info->child_out_r);
    CloseHandle(info->child_out_w);
}

/* Start a subprocess with run_command_redirected and register it with the
   termination handler. Takes care of o.shellexec. Returns the PID of the
   subprocess or -1 on error. */
static int start_subprocess(char* cmdexec, struct subprocess_info* info)
{
    char* cmdbuf;
    int pid;

    //if (o.execmode == EXEC_SHELL) {
    //    /* Run with cmd.exe. */
    //    const char* shell;
    //    size_t cmdlen;

    //    shell = get_shell();
    //    cmdlen = strlen(shell) + strlen(cmdexec) + 32;
    //    cmdbuf = (char*)malloc(cmdlen);
    //    snprintf(cmdbuf, cmdlen, "%s /C %s", shell, cmdexec);
    //}
    //else {
    //    cmdbuf = cmdexec;
    //}
    cmdbuf = cmdexec;
    
    //if (o.debug)
        //logdebug("Executing: %s\n", cmdbuf);

    pid = run_command_redirected(cmdbuf, info);

    if (cmdbuf != cmdexec)
        free(cmdbuf);

    if (pid == -1)
        return -1;

    if (register_subprocess(info->proc) == -1) {
        //if (o.verbose)
            //logdebug("Couldn't register subprocess with termination handler; not executing.\n");
        TerminateProcess(info->proc, 2);
        subprocess_info_close(info);
        return -1;
    }

    return pid;
}

/* Do a recv on an fdinfo, without other side effects. */
int fdinfo_recv(struct fdinfo* fdn, char* buf, size_t size)
{
    return recv(fdn->fd, buf, size, 0);
}

int fdinfo_pending(struct fdinfo* fdn)
{
    return 0;
}

int unblock_socket(int sd) {
#ifdef WIN32
    unsigned long one = 1;

    ioctlsocket(sd, FIONBIO, &one);

    return 0;
#else
    int options;

    /* Unblock our socket to prevent recvfrom from blocking forever on certain
     * target ports. */
    options = fcntl(sd, F_GETFL);
    if (options == -1)
        return -1;

    return fcntl(sd, F_SETFL, O_NONBLOCK | options);
#endif /* WIN32 */
}

/* Convert a socket to blocking mode */
int block_socket(int sd) {
#ifdef WIN32
    unsigned long options = 0;

    ioctlsocket(sd, FIONBIO, &options);

    return 0;
#else
    int options;

    options = fcntl(sd, F_GETFL);
    if (options == -1)
        return -1;

    return fcntl(sd, F_SETFL, (~O_NONBLOCK) & options);
#endif
}

int ncat_recv(struct fdinfo* fdn, char* buf, size_t size, int* pending)
{
    int n;

    *pending = 0;

    n = fdinfo_recv(fdn, buf, size);

    if (n <= 0)
        return n;

    //if (0)
    //    ncat_delay_timer(0);
    //if (0)
    //    dotelnet(fdn->fd, (unsigned char*)buf, n);
    //ncat_log_recv(buf, n);

    /* SSL can buffer our input, so doing another select() won't necessarily
       work for us. Indicate to the caller that this function must be called
       again to get more data. */
    *pending = fdinfo_pending(fdn);

    return n;
}

/* Do a send on an fdinfo, without any logging or other side effects. */
int fdinfo_send(struct fdinfo* fdn, const char* buf, size_t size)
{
    return send(fdn->fd, buf, size, 0);
}

static int blocking_fdinfo_send(struct fdinfo* fdn, const char* buf, size_t size)
{
    int ret;

    block_socket(fdn->fd);
    ret = fdinfo_send(fdn, buf, size);
    unblock_socket(fdn->fd);

    return ret;
}

int ncat_send(struct fdinfo* fdn, const char* buf, size_t size)
{
    int n;

    if (0)
        return size;

    n = blocking_fdinfo_send(fdn, buf, size);
    if (n <= 0)
        return n;

    //ncat_log_send(buf, size);

    return n;
}

int fix_line_endings(char* src, int* len, char** dst, int* state)
{
    int fix_count;
    int i, j;
    int num_bytes = *len;
    int prev_state = *state;

    /* *state is true iff the last byte of the previous block was \r. */
    if (num_bytes > 0)
        *state = (src[num_bytes - 1] == '\r');

    /* get count of \n without matching \r */
    fix_count = 0;
    for (i = 0; i < num_bytes; i++) {
        if (src[i] == '\n' && ((i == 0) ? !prev_state : src[i - 1] != '\r'))
            fix_count++;
    }
    if (fix_count <= 0)
        return 0;

    /* now insert matching \r */
    *dst = (char*)malloc(num_bytes + fix_count);
    j = 0;

    for (i = 0; i < num_bytes; i++) {
        if (src[i] == '\n' && ((i == 0) ? !prev_state : src[i - 1] != '\r')) {
            memcpy(*dst + j, "\r\n", 2);
            j += 2;
        }
        else {
            memcpy(*dst + j, src + i, 1);
            j++;
        }
    }
    *len += fix_count;

    return 1;
}

/* Relay data between a socket and a process until the process dies or stops
   sending or receiving data. The socket descriptor and process pipe handles
   are in the data argument, which must be a pointer to struct subprocess_info.

   This function is a workaround for the fact that we can't just run a process
   after redirecting its input handles to a socket. If the process, for
   example, redirects its own stdin, it somehow confuses the socket and stdout
   stops working. This is exactly what ncat does (as part of the Windows stdin
   workaround), so it can't be ignored.

   This function can be invoked through CreateThread to simulate fork+exec, or
   called directly to simulate exec. It frees the subprocess_info struct and
   closes the socket and pipe handles before returning. Returns the exit code
   of the subprocess. */
static DWORD WINAPI subprocess_thread_func(void* data)
{
    struct subprocess_info* info;
    char pipe_buffer[1024];
    OVERLAPPED overlap = { 0 };
    HANDLE events[3];
    DWORD ret, rc;
    int crlf_state = 0;

    info = (struct subprocess_info*)data;

    /* Three events we watch for: socket read, pipe read, and process end. */
    events[0] = (HANDLE)WSACreateEvent();
    WSAEventSelect(info->fdn.fd, events[0], FD_READ | FD_CLOSE);
    events[1] = info->child_out_r;
    events[2] = info->proc;

    /* To avoid blocking or polling, we use asynchronous I/O, or what Microsoft
       calls "overlapped" I/O, on the process pipe. WaitForMultipleObjects
       reports when the read operation is complete. */
    ReadFile(info->child_out_r, pipe_buffer, sizeof(pipe_buffer), NULL, &overlap);

    /* Loop until EOF or error. */
    for (;;) {
        DWORD n_r, n_w;
        int i, n;
        char* crlf = NULL, * wbuf;
        char buffer[1024];
        int pending;

        i = WaitForMultipleObjects(3, events, FALSE, INFINITE);
        switch (i) {
        case WAIT_OBJECT_0:
            /* Read from socket, write to process. */

            /* Reset events on the socket. SSL_read in particular does not
             * clear the event. */
            ResetEvent(events[0]);
            WSAEventSelect(info->fdn.fd, events[0], 0);
            block_socket(info->fdn.fd);
            do {
                n = ncat_recv(&info->fdn, buffer, sizeof(buffer), &pending);
                if (n <= 0)
                {
                    goto loop_end;
                }
                n_r = n;
                if (WriteFile(info->child_in_w, buffer, n_r, &n_w, NULL) == 0)
                {
                    goto loop_end;
                }
                if (n_w != n)
                {
                    goto loop_end;
                }
            } while (pending);
            /* Restore the select event (and non-block the socket again.) */
            WSAEventSelect(info->fdn.fd, events[0], FD_READ | FD_CLOSE);
            /* Fall through to check other objects */
        case WAIT_OBJECT_0 + 1:
            /* Read from process, write to socket. */
            if (GetOverlappedResult(info->child_out_r, &overlap, &n_r, FALSE)) {
                wbuf = pipe_buffer;
                if (1) {
                    n = n_r;
                    if (fix_line_endings((char*)pipe_buffer, &n, &crlf, &crlf_state))
                        wbuf = crlf;
                    n_r = n;
                }
                /* The above call to WSAEventSelect puts the socket in
                   non-blocking mode, but we want this send to block, not
                   potentially return WSAEWOULDBLOCK. We call block_socket, but
                   first we must clear out the select event. */
                WSAEventSelect(info->fdn.fd, events[0], 0);
                block_socket(info->fdn.fd);
                n = ncat_send(&info->fdn, wbuf, n_r);
                if (crlf != NULL)
                    free(crlf);
                if (n != n_r)
                {
                    goto loop_end;
                }
                /* Restore the select event (and non-block the socket again.) */
                WSAEventSelect(info->fdn.fd, events[0], FD_READ | FD_CLOSE);
                /* Queue another asychronous read. */
                ReadFile(info->child_out_r, pipe_buffer, sizeof(pipe_buffer), NULL, &overlap);
            }
            else {
                /* Probably read result wasn't ready, but we got here because
                 * there was data on the socket. */
                switch (GetLastError()) {
                case ERROR_IO_PENDING:
                case ERROR_IO_INCOMPLETE:
                    break;
                default:
                    /* Error or end of file. */
                    goto loop_end;
                    break;
                }
            }
            /* Break here, don't go on. Need to finish all socket writes before
             * checking if child process died. */
            break;
        case WAIT_OBJECT_0 + 2:
            /* The child died. There are no more writes left in the pipe
               because WaitForMultipleObjects guarantees events with lower
               indexes are handled first. */
        default:
            goto loop_end;
            break;
        }
    }

loop_end:

    WSACloseEvent(events[0]);

    rc = unregister_subprocess(info->proc);
    //ncat_assert(rc != -1);

    GetExitCodeProcess(info->proc, &ret);
    if (ret == STILL_ACTIVE) {
       // if (o.debug > 1)
            //logdebug("Subprocess still running, terminating it.\n");
        rc = TerminateProcess(info->proc, 0);
        if (rc == 0) {
            //if (o.debug > 1)
                //logdebug("TerminateProcess failed with code %d.\n", rc);
        }
    }
    GetExitCodeProcess(info->proc, &ret);
   // if (o.debug > 1)
        //logdebug("Subprocess ended with exit code %d.\n", ret);

    shutdown(info->fdn.fd, 2);
    subprocess_info_close(info);
    free(info);

    rc = WaitForSingleObject(pseudo_sigchld_mutex, INFINITE);
    //ncat_assert(rc == WAIT_OBJECT_0);
    if (pseudo_sigchld_handler != NULL)
        pseudo_sigchld_handler();
    rc = ReleaseMutex(pseudo_sigchld_mutex);
    //ncat_assert(rc != 0);

    return ret;
}

/* Find a free slot in the subprocesses table. Update subprocesses_max_index to
   be one greater than the maximum index containing a non-NULL handle. (It is
   assumed that the index returned by this function will be filled by a
   handle.) */
static int get_subprocess_slot(void)
{
    int i, free_index, max_index;
    DWORD rc;

    rc = WaitForSingleObject(subprocesses_mutex, INFINITE);
    //ncat_assert(rc == WAIT_OBJECT_0);

    free_index = -1;
    max_index = 0;
    for (i = 0; i < subprocess_max_index; i++) {
        HANDLE proc = subprocesses[i];

        if (proc == NULL) {
            if (free_index == -1)
                free_index = i;
        }
        else {
            max_index = i + 1;
        }
    }
    if ((free_index == -1 || free_index == max_index)
        && max_index < sizeof(subprocesses) / sizeof(subprocesses[0]))
        free_index = max_index++;
    subprocess_max_index = max_index;

    rc = ReleaseMutex(subprocesses_mutex);
    //ncat_assert(rc != 0);

    return free_index;
}

/* Add a process to the list of processes to kill at program exit. Once you
   call this function, the process handle "belongs" to it and you shouldn't
   modify the handle until you call unregister_subprocess. Returns -1 on
   error. */
static int register_subprocess(HANDLE proc)
{
    int i;
    DWORD rc;

    if (subprocesses_mutex == NULL) {
        subprocesses_mutex = CreateMutex(NULL, FALSE, NULL);
        //ncat_assert(subprocesses_mutex != NULL);
    }
    if (pseudo_sigchld_mutex == NULL) {
        pseudo_sigchld_mutex = CreateMutex(NULL, FALSE, NULL);
        //ncat_assert(pseudo_sigchld_mutex != NULL);
    }

    rc = WaitForSingleObject(subprocesses_mutex, INFINITE);
    //ncat_assert(rc == WAIT_OBJECT_0);

    i = get_subprocess_slot();
    if (i == -1) {
        ////if (o.verbose)
            //logdebug("No free process slots for termination handler.\n");
    }
    else {
        subprocesses[i] = proc;

       // if (o.debug > 1)
            //logdebug("Register subprocess %p at index %d.\n", proc, i);

        if (!atexit_registered) {
            /* We register both an atexit and a SIGINT handler because ^C
               doesn't seem to cause atexit handlers to be called. */
            atexit(terminate_subprocesses);
            //signal(SIGINT, sigint_handler);
            atexit_registered = 1;
        }
    }

    rc = ReleaseMutex(subprocesses_mutex);
    //ncat_assert(rc != 0);

    return i;
}

/* Remove a process handle from the termination handler list. Returns -1 if the
   process was not already registered. */
static int unregister_subprocess(HANDLE proc)
{
    int i;
    DWORD rc;

    rc = WaitForSingleObject(subprocesses_mutex, INFINITE);
    //ncat_assert(rc == WAIT_OBJECT_0);

    for (i = 0; i < subprocess_max_index; i++) {
        if (proc == subprocesses[i])
            break;
    }
    if (i < subprocess_max_index) {
        subprocesses[i] = NULL;
        //if (o.debug > 1)
            //logdebug("Unregister subprocess %p from index %d.\n", proc, i);
    }
    else {
        i = -1;
    }

    rc = ReleaseMutex(subprocesses_mutex);
    //ncat_assert(rc != 0);

    return i;
}

static void terminate_subprocesses(void)
{
    int i;
    DWORD rc;

    //if (o.debug)
        //logdebug("Terminating subprocesses\n");

    rc = WaitForSingleObject(subprocesses_mutex, INFINITE);
    //ncat_assert(rc == WAIT_OBJECT_0);

   // if (o.debug > 1)
        //logdebug("max_index %d\n", subprocess_max_index);
    for (i = 0; i < subprocess_max_index; i++) {
        HANDLE proc = subprocesses[i];
        DWORD ret;

        if (proc == NULL)
            continue;
        GetExitCodeProcess(proc, &ret);
        if (ret == STILL_ACTIVE) {
           // if (o.debug > 1)
                //logdebug("kill index %d\n", i);
            TerminateProcess(proc, 0);
        }
        subprocesses[i] = NULL;
    }

    rc = ReleaseMutex(subprocesses_mutex);
    //ncat_assert(rc != 0);
}

static void sigint_handler(int s)
{
    terminate_subprocesses();
    ExitProcess(0);
}