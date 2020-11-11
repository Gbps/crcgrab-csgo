use std::mem;

use winapi::um::{errhandlingapi, winbase};
use winapi::um::winbase::{FORMAT_MESSAGE_ALLOCATE_BUFFER, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS, LocalFree};
use winapi::um::winnt::{MAKELANGID, LANG_NEUTRAL, SUBLANG_DEFAULT};
use std::ptr;
use widestring::WideCString;

pub struct Win32ErrorFormatter
{}

impl Win32ErrorFormatter
{
    pub fn error_str() -> String
    {
        unsafe {
            // get the last error from the OS
            let err = errhandlingapi::GetLastError();

            // let the OS allocate a buffer for us and return the buffer pointer into message_buffer
            let mut message_buffer: mem::MaybeUninit<*const u8> = mem::MaybeUninit::uninit();
            let size: usize = winbase::FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                                      ptr::null_mut(),
                                                      err,
                                                      MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT) as u32,
                                                      message_buffer.as_mut_ptr().cast(),
                                                      0, ptr::null_mut(),
            ) as usize;

            // formatting the message failed
            if size == 0 || message_buffer.assume_init().is_null() {
                return String::from("<Error message unknown>");
            }

            // convert to utf8 String
            let msg_string = std::str::from_utf8_unchecked(std::slice::from_raw_parts(message_buffer.assume_init(), size)).to_string();

            // free the old buffer we just copied
            LocalFree(message_buffer.assume_init() as _);

            return msg_string;
        }
    }
}
pub struct Win32Strings
{}

impl Win32Strings
{
    /// get a string from a wide utf-16 string
    pub unsafe fn from_utf16(ptr: *const u16) -> String
    {
        WideCString::from_ptr_str(ptr).to_string().unwrap()
    }

    /// get a string from a wide utf-16 string
    pub unsafe fn from_utf16_unchecked(ptr: *const u16, len: usize) -> String
    {
        WideCString::from_ptr_unchecked(ptr, len).to_string().unwrap()
    }
}