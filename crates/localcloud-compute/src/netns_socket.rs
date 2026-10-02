//! Open a TCP socket inside a rootless OCI network namespace without an external helper.
//! A child process is required: Linux rejects entering a user namespace from a
//! multithreaded process. The child executes only libc calls after fork and returns
//! the connected descriptor through SCM_RIGHTS.
use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;
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

/// Bind a loopback listener in a task's network namespace and pass its socket
/// back to the host. Accepted sockets retain the namespace's network identity.
pub(crate) fn bind_listener(
    user_ns: std::fs::File,
    net_ns: std::fs::File,
    address: Ipv4Addr,
    port: u16,
) -> io::Result<std::net::TcpListener> {
    let listener = std::net::TcpListener::from(bind_socket(
        user_ns,
        net_ns,
        address,
        port,
        libc::SOCK_STREAM,
    )?);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

pub(crate) fn bind_udp(
    user_ns: std::fs::File,
    net_ns: std::fs::File,
    address: Ipv4Addr,
    port: u16,
) -> io::Result<std::net::UdpSocket> {
    let socket = std::net::UdpSocket::from(bind_socket(
        user_ns,
        net_ns,
        address,
        port,
        libc::SOCK_DGRAM,
    )?);
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn bind_socket(
    user_ns: std::fs::File,
    net_ns: std::fs::File,
    address: Ipv4Addr,
    port: u16,
    socket_type: i32,
) -> io::Result<OwnedFd> {
    let mut pair = [-1; 2];
    // SAFETY: pair points to storage for two descriptors.
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
    // SAFETY: child performs only libc calls and exits without unwinding.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }
    if pid == 0 {
        let status = unsafe {
            bind_child_main(
                parent.as_raw_fd(),
                child.as_raw_fd(),
                user_ns.as_raw_fd(),
                net_ns.as_raw_fd(),
                address,
                port,
                socket_type,
            )
        };
        // SAFETY: don't run inherited Tokio state in the forked child.
        unsafe { libc::_exit(status) };
    }
    drop(child);
    let received = receive_fd(parent.as_raw_fd()).map(|fd| {
        // SAFETY: SCM_RIGHTS delivered one owned descriptor.
        unsafe { OwnedFd::from_raw_fd(fd) }
    });
    let mut status = 0;
    loop {
        // SAFETY: pid is our child; status has valid storage.
        if unsafe { libc::waitpid(pid, &mut status, 0) } >= 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
    received
}

unsafe fn bind_child_main(
    parent: i32,
    channel: i32,
    user_ns: i32,
    net_ns: i32,
    address: Ipv4Addr,
    port: u16,
    socket_type: i32,
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
    if address != Ipv4Addr::LOCALHOST && !add_loopback_address(address) {
        send_error(channel, 11);
        return 11;
    }
    let socket = libc::socket(libc::AF_INET, socket_type | libc::SOCK_CLOEXEC, 0);
    if socket < 0 {
        send_error(channel, 3);
        return 3;
    }
    let one: i32 = 1;
    if libc::setsockopt(
        socket,
        libc::SOL_SOCKET,
        libc::SO_REUSEADDR,
        (&one as *const i32).cast(),
        size_of::<i32>() as u32,
    ) != 0
    {
        send_error(channel, 9);
        libc::close(socket);
        return 9;
    }
    let address = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(address.octets()),
        },
        sin_zero: [0; 8],
    };
    if libc::bind(
        socket,
        (&address as *const libc::sockaddr_in).cast(),
        size_of::<libc::sockaddr_in>() as u32,
    ) != 0
        || (socket_type == libc::SOCK_STREAM && libc::listen(socket, 128) != 0)
    {
        send_error(channel, 10);
        libc::close(socket);
        return 10;
    }
    let sent = send_fd(channel, socket);
    libc::close(socket);
    if sent {
        0
    } else {
        7
    }
}

#[repr(C)]
struct IfAddrMessage {
    family: u8,
    prefix_len: u8,
    flags: u8,
    scope: u8,
    index: u32,
}

#[repr(C)]
struct RouteAttribute {
    len: u16,
    kind: u16,
}

#[repr(C)]
struct AddAddress {
    header: libc::nlmsghdr,
    body: IfAddrMessage,
    attr: RouteAttribute,
    address: [u8; 4],
}

/// Add a /32 alias to loopback in the already-entered guest namespace.
/// Netlink avoids a dependency on `ip` or a shell inside the OCI guest.
unsafe fn add_loopback_address(address: Ipv4Addr) -> bool {
    let index = libc::if_nametoindex(c"lo".as_ptr());
    if index == 0 {
        return false;
    }
    let fd = libc::socket(
        libc::AF_NETLINK,
        libc::SOCK_RAW | libc::SOCK_CLOEXEC,
        libc::NETLINK_ROUTE,
    );
    if fd < 0 {
        return false;
    }
    let timeout = libc::timeval {
        tv_sec: 2,
        tv_usec: 0,
    };
    if libc::setsockopt(
        fd,
        libc::SOL_SOCKET,
        libc::SO_RCVTIMEO,
        (&timeout as *const libc::timeval).cast(),
        size_of::<libc::timeval>() as u32,
    ) != 0
    {
        libc::close(fd);
        return false;
    }
    let request = AddAddress {
        header: libc::nlmsghdr {
            nlmsg_len: size_of::<AddAddress>() as u32,
            nlmsg_type: libc::RTM_NEWADDR,
            nlmsg_flags: (libc::NLM_F_REQUEST
                | libc::NLM_F_ACK
                | libc::NLM_F_CREATE
                | libc::NLM_F_EXCL) as u16,
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        body: IfAddrMessage {
            family: libc::AF_INET as u8,
            prefix_len: 32,
            flags: 0,
            scope: 0,
            index,
        },
        attr: RouteAttribute {
            len: (size_of::<RouteAttribute>() + 4) as u16,
            kind: 2, // IFA_LOCAL
        },
        address: address.octets(),
    };
    let mut kernel: libc::sockaddr_nl = zeroed();
    kernel.nl_family = libc::AF_NETLINK as u16;
    let sent = libc::sendto(
        fd,
        (&request as *const AddAddress).cast(),
        size_of::<AddAddress>(),
        0,
        (&kernel as *const libc::sockaddr_nl).cast(),
        size_of::<libc::sockaddr_nl>() as u32,
    );
    let mut reply = [0u8; 256];
    let received = if sent == size_of::<AddAddress>() as isize {
        libc::recv(fd, reply.as_mut_ptr().cast(), reply.len(), 0)
    } else {
        -1
    };
    libc::close(fd);
    if received < (size_of::<libc::nlmsghdr>() + size_of::<i32>()) as isize {
        return false;
    }
    let header = std::ptr::read_unaligned(reply.as_ptr().cast::<libc::nlmsghdr>());
    let error =
        std::ptr::read_unaligned(reply[size_of::<libc::nlmsghdr>()..].as_ptr().cast::<i32>());
    header.nlmsg_type == libc::NLMSG_ERROR as u16 && (error == 0 || error == -libc::EEXIST)
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
