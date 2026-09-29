//! Open a TCP socket inside a rootless OCI network namespace without an external helper.
//! A child process is required: Linux rejects entering a user namespace from a
//! multithreaded process. The child executes only libc calls after fork and returns
//! the connected descriptor through SCM_RIGHTS.
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

pub(crate) fn connect(
    user_ns: std::fs::File,
    net_ns: std::fs::File,
    port: u16,
    timeout: Duration,
) -> io::Result<std::net::TcpStream> {
    let mut pair = [-1; 2];
    // SAFETY: pair has space for two descriptors and is initialized by socketpair.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: socketpair returned two owned descriptors.
    let parent = unsafe { OwnedFd::from_raw_fd(pair[0]) };
    let child = unsafe { OwnedFd::from_raw_fd(pair[1]) };
    // SAFETY: the child uses libc calls only, then exits without running Rust destructors.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let status = unsafe {
            child_main(
                parent.as_raw_fd(),
                child.as_raw_fd(),
                user_ns.as_raw_fd(),
                net_ns.as_raw_fd(),
                port,
                timeout,
            )
        };
        // SAFETY: terminate the child without unwinding through inherited runtime state.
        unsafe { libc::_exit(status) };
    }
    drop(child);
    let received = receive_fd(parent.as_raw_fd()).map(|fd| {
        // SAFETY: SCM_RIGHTS delivered an owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    let mut status = 0;
    loop {
        // SAFETY: pid is the child returned by fork, status points to valid storage.
        if unsafe { libc::waitpid(pid, &mut status, 0) } >= 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    let fd = received?;
    let stream = std::net::TcpStream::from(fd);
    stream.set_nonblocking(true)?;
    Ok(stream)
}

unsafe fn child_main(
    parent: i32,
    channel: i32,
    user_ns: i32,
    net_ns: i32,
    port: u16,
    timeout: Duration,
) -> i32 {
    libc::close(parent);
    if !close_inherited_fds(channel, user_ns, net_ns) {
        send_error(channel, 8);
        return 8;
    }
    if libc::setns(user_ns, libc::CLONE_NEWUSER) != 0 {
        send_error(channel, 1);
        return 1;
    }
    if libc::setns(net_ns, libc::CLONE_NEWNET) != 0 {
        send_error(channel, 2);
        return 2;
    }
    let socket = libc::socket(
        libc::AF_INET,
        libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        0,
    );
    if socket < 0 {
        send_error(channel, 3);
        return 3;
    }
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes([127, 0, 0, 1]),
        },
        sin_zero: [0; 8],
    };
    let connected = libc::connect(
        socket,
        (&address as *const libc::sockaddr_in).cast(),
        size_of::<libc::sockaddr_in>() as u32,
    );
    if connected != 0 {
        let errno = *libc::__errno_location();
        if errno != libc::EINPROGRESS {
            send_error(channel, 4);
            libc::close(socket);
            return 4;
        }
        let mut pollfd = libc::pollfd {
            fd: socket,
            events: libc::POLLOUT,
            revents: 0,
        };
        let millis = timeout.as_millis().min(i32::MAX as u128) as i32;
        if libc::poll(&mut pollfd, 1, millis) <= 0 {
            send_error(channel, 5);
            libc::close(socket);
            return 5;
        }
        let mut error = 0;
        let mut len = size_of::<i32>() as libc::socklen_t;
        if libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&mut error as *mut i32).cast(),
            &mut len,
        ) != 0
            || error != 0
        {
            send_error(channel, 6);
            libc::close(socket);
            return 6;
        }
    }
    let sent = send_fd(channel, socket);
    libc::close(socket);
    if sent {
        0
    } else {
        7
    }
}

unsafe fn close_inherited_fds(channel: i32, user_ns: i32, net_ns: i32) -> bool {
    // Keep only the IPC channel and the two namespace handles. close_range is a
    // Linux syscall and does not call Rust allocation or libc's process locks.
    let mut keep = [channel as u32, user_ns as u32, net_ns as u32];
    keep.sort_unstable();
    let mut next = 0u32;
    for fd in keep {
        if fd > next && libc::syscall(libc::SYS_close_range, next, fd - 1, 0u32) != 0 {
            return false;
        }
        next = fd.saturating_add(1);
    }
    libc::syscall(libc::SYS_close_range, next, u32::MAX, 0u32) == 0
}

unsafe fn send_error(channel: i32, code: u8) {
    libc::send(channel, (&code as *const u8).cast(), 1, libc::MSG_NOSIGNAL);
}

unsafe fn send_fd(channel: i32, socket: i32) -> bool {
    let byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&byte as *const u8).cast_mut().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    let mut msg: libc::msghdr = zeroed();
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = libc::CMSG_SPACE(size_of::<i32>() as u32) as usize;
    let cmsg = libc::CMSG_FIRSTHDR(&msg);
    if cmsg.is_null() {
        return false;
    }
    (*cmsg).cmsg_level = libc::SOL_SOCKET;
    (*cmsg).cmsg_type = libc::SCM_RIGHTS;
    (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<i32>() as u32) as usize;
    std::ptr::copy_nonoverlapping(
        (&socket as *const i32).cast::<u8>(),
        libc::CMSG_DATA(cmsg),
        size_of::<i32>(),
    );
    libc::sendmsg(channel, &msg, libc::MSG_NOSIGNAL) == 1
}

fn receive_fd(channel: i32) -> io::Result<i32> {
    let mut byte = 0u8;
    let mut iov = libc::iovec {
        iov_base: (&mut byte as *mut u8).cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 8];
    // SAFETY: msg points to initialized iovec and control storage for recvmsg.
    let mut msg: libc::msghdr = unsafe { zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = size_of::<[usize; 8]>();
    // SAFETY: channel is an open Unix socket; msg storage is valid.
    let received = loop {
        let count = unsafe { libc::recvmsg(channel, &mut msg, libc::MSG_CMSG_CLOEXEC) };
        if count >= 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break count;
        }
    };
    if received <= 0 {
        return Err(if received == 0 {
            io::Error::new(io::ErrorKind::BrokenPipe, "OCI connector child exited")
        } else {
            io::Error::last_os_error()
        });
    }
    if byte != 0 {
        return Err(io::Error::other(format!(
            "OCI namespace connector failed at stage {byte}"
        )));
    }
    if msg.msg_flags & libc::MSG_CTRUNC != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI connector control message was truncated",
        ));
    }
    // SAFETY: recvmsg populated the control message and CMSG_FIRSTHDR validates bounds.
    let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    if cmsg.is_null()
        || unsafe {
            (*cmsg).cmsg_level != libc::SOL_SOCKET
                || (*cmsg).cmsg_type != libc::SCM_RIGHTS
                || (*cmsg).cmsg_len < libc::CMSG_LEN(size_of::<i32>() as u32) as usize
        }
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI connector returned no TCP descriptor",
        ));
    }
    let mut fd = -1;
    // SAFETY: SCM_RIGHTS control data contains one i32 descriptor.
    unsafe {
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            (&mut fd as *mut i32).cast::<u8>(),
            size_of::<i32>(),
        );
    }
    if fd < 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OCI connector returned invalid descriptor",
        ));
    }
    Ok(fd)
}
