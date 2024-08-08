//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::io;
use std::io::Error;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::Framed;
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, GetLastError, FALSE, HANDLE, TRUE, WAIT_EVENT, WAIT_FAILED, WAIT_OBJECT_0,
    },
    System::Threading::{CreateEventA, SetEvent, WaitForMultipleObjects, INFINITE},
};

use super::TunPacketCodec;
use crate::device::AbstractDevice;
use crate::platform::Device;

/// An async TUN device wrapper around a TUN device.
pub struct AsyncDevice {
    inner: Device,
    session: WinSession,
}

/// Returns a shared reference to the underlying Device object.
impl core::ops::Deref for AsyncDevice {
    type Target = Device;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

/// Returns a mutable reference to the underlying Device object.
impl core::ops::DerefMut for AsyncDevice {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl AsyncDevice {
    /// Create a new `AsyncDevice` wrapping around a `Device`.
    pub fn new(device: Device) -> io::Result<AsyncDevice> {
        let session = WinSession::new(device.tun.get_session())?;
        Ok(AsyncDevice {
            inner: device,
            session,
        })
    }

    /// Consumes this AsyncDevice and return a Framed object (unified Stream and Sink interface)
    pub fn into_framed(self) -> Framed<Self, TunPacketCodec> {
        let mtu = self.mtu().unwrap_or(crate::DEFAULT_MTU);
        let codec = TunPacketCodec::new(mtu as usize);
        // guarantee to avoid the mtu of wintun may far away larger than the default provided capacity of ReadBuf of Framed
        Framed::with_capacity(self, codec, mtu as usize)
    }

    /// Recv a packet from tun device - Not implemented for windows
    pub async fn recv(&self, _buf: &mut [u8]) -> std::io::Result<usize> {
        unimplemented!()
    }

    /// Send a packet to tun device - Not implemented for windows
    pub async fn send(&self, _buf: &[u8]) -> std::io::Result<usize> {
        unimplemented!()
    }
}

impl AsyncRead for AsyncDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.session).poll_read(cx, buf)
    }
}

impl AsyncWrite for AsyncDevice {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        Pin::new(&mut self.session).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.session).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Pin::new(&mut self.session).poll_shutdown(cx)
    }
}

/// A wrapper struct that allows a type to be Send and Sync
#[derive(Copy, Clone, Debug)]
struct UnsafeHandle(pub HANDLE);

/// We never read from the pointer. It only serves as a handle we pass
/// to the kernel or C code that doesn't have the same mutable aliasing
/// restrictions we have in Rust.
unsafe impl Send for UnsafeHandle {}
unsafe impl Sync for UnsafeHandle {}

struct WinSession {
    session: std::sync::Arc<wintun::Session>,
    waker: std::sync::Arc<std::sync::Mutex<Option<std::task::Waker>>>,
    thread: Option<std::thread::JoinHandle<()>>,
    shutdown_event: std::sync::Arc<UnsafeHandle>,
}

impl WinSession {
    fn new(session: std::sync::Arc<wintun::Session>) -> Result<WinSession, io::Error> {
        let session_reader = session.clone();
        let waker = std::sync::Arc::new(std::sync::Mutex::new(None::<std::task::Waker>));
        let shutdown_event = unsafe {
            let handle_ptr = CreateEventA(std::ptr::null_mut(), FALSE, FALSE, std::ptr::null_mut());
            if handle_ptr.is_null() {
                return Err(io::Error::last_os_error());
            }
            std::sync::Arc::new(UnsafeHandle(handle_ptr))
        };

        let task = std::thread::spawn({
            let wait_waker = waker.clone();
            let read_wait_event = session_reader.get_read_wait_event().unwrap();
            let shutdown_event = shutdown_event.clone();
            move || {
                let handles = [read_wait_event, shutdown_event.0 as wintun::HANDLE];
                loop {
                    // SAFETY: We abide by the requirements of WaitForMultipleObjects,
                    // an event handle is a pointer to valid, aligned, stack memory.
                    let result = unsafe {
                        WaitForMultipleObjects(
                            handles.len() as _,
                            handles.as_ptr() as _,
                            FALSE,
                            INFINITE,
                        )
                    };
                    const WAIT_OBJECT_1: WAIT_EVENT = WAIT_OBJECT_0 + 1;
                    match result {
                        WAIT_OBJECT_0 => {
                            // We have data, then wake up the wating waker.
                            if let Some(waker) = wait_waker.lock().unwrap().take() {
                                waker.wake();
                            }
                        }
                        WAIT_OBJECT_1 => {
                            // We receive a shutdown signal, close the session.
                            break;
                        }
                        WAIT_FAILED => {
                            // We don’t know the exact reason for the failure.
                            let last_error_code = unsafe { GetLastError() };
                            log::warn!(
                                "WaitForMultipleObjects failed, last error: {:?}",
                                last_error_code
                            );
                        }
                        _ => {
                            // This should never happen on all cases matched.
                            unreachable!(
                                "WaitForMultipleObjects returned unexpected result {:?}",
                                result
                            );
                        }
                    }
                }
                // SAFETY: We only close this valid shutdown handle once.
                _ = unsafe { CloseHandle(shutdown_event.0 as _) };
            }
        });

        Ok(WinSession {
            session,
            waker,
            thread: Some(task),
            shutdown_event,
        })
    }
}

impl Drop for WinSession {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            // SAFETY: We can set the shutdown event handle to the
            // signaled state when the shutdown handle is not close.
            if unsafe { SetEvent(self.shutdown_event.0) } == TRUE {
                // Only join the event thread which may be responsive.
                _ = thread.join();
            } else {
                // We won't join the thread which may be unresponsive.
                let last_error_code = unsafe { GetLastError() };
                log::warn!("SetEvent failed, last error: {:?}", last_error_code);
            }
        }
    }
}

impl AsyncRead for WinSession {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.session.try_receive() {
            Ok(Some(bytes)) => {
                // We have data, then copy and push to the buffer.
                buf.put_slice(&bytes.bytes());
                std::task::Poll::Ready(Ok(()))
            }
            Ok(None) => {
                // Ensure the future can wake up when we have data.
                self.waker.lock().unwrap().replace(cx.waker().clone());
                Poll::Pending
            }
            Err(err) => Poll::Ready(Err(err.into())),
        }
    }
}

impl AsyncWrite for WinSession {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let mut write_pack = self.session.allocate_send_packet(buf.len() as u16)?;
        write_pack.bytes_mut().copy_from_slice(buf.as_ref());
        self.session.send_packet(write_pack);
        std::task::Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        Poll::Ready(Ok(()))
    }
}
