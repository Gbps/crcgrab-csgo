use crate::loader::win32util::*;

use winapi::shared::minwindef::{HINSTANCE, HMODULE};
use winapi::um::{libloaderapi, processthreadsapi, psapi};
use std::mem;

use anyhow::{Result, Context};
use widestring::WideCString;
use std::sync::Arc;
use crate::loader::{ProcessHandle, AutoHandle};
use winapi::um::winnt::HANDLE;
use crate::loader::SignatureItem::{Wildcard, Byte};

/// A sig-scanning signature
pub enum SignatureItem
{
    /// A concrete byte in the signature
    Byte(u8),

    /// A wildcard character
    Wildcard,
}

/// A reference to a remote DLL in another process
pub struct RemoteDllRef
{
    /// the remote HMODULE handle
    handle: HMODULE,

    /// the process this module belongs to
    process: Arc<AutoHandle>,
}

impl RemoteDllRef
{
    /// create a handle object using a remote module handle an
    pub (crate) fn from_handle(handle: HMODULE, process: Arc<AutoHandle>) -> Self
    {
        return Self {
            handle,
            process
        }
    }

    /// get the base name of the module
    pub fn get_name(&self) -> Result<String>
    {
        return unsafe{ DllRef::get_name_common(self.handle, **self.process) }
    }

    /// get the remote base address of the module
    pub fn get_remote_base(&self) -> usize
    {
        self.handle as usize
    }


}

pub struct DllRef
{
    // OS handle to the library
    handle: HINSTANCE,

    // base address of the library
    base: *mut u8,

    // the size of the library as mapped in memory
    size: usize,
}

/*
impl Drop for DllRef
{
    // free the library reference
    fn drop(&mut self) {
        unsafe {
            libloaderapi::FreeLibrary(self.handle);
        }
    }
}
*/

impl DllRef
{
    /// get the module name of the dll
    unsafe fn get_name_common(handle: HMODULE, process: HANDLE) -> Result<String>
    {
        // read the name of the module from the handle
        let mut out_name = mem::MaybeUninit::<[i16; 256]>::uninit();
        let sz = psapi::GetModuleBaseNameW(
            process,
            handle,
            out_name.as_mut_ptr().cast(),
            mem::size_of_val(&out_name) as u32,
        );
        if sz == 0 {
            return Err(anyhow::anyhow!("GetModuleBaseNameW failed, handle might be invalid"));
        }

        // and convert to wide string
        let name = Win32Strings::from_utf16_unchecked(out_name.as_ptr().cast(), sz as usize);

        return Ok(name)
    }

    /// get the base name of the module
    pub fn get_name(&self) -> Result<String>
    {
        return unsafe { Self::get_name_common(self.handle, processthreadsapi::GetCurrentProcess()) }
    }

    /// create a dll reference by a handle
    pub (crate) fn from_handle(handle: HINSTANCE) -> Result<Self>
    {
        unsafe {
            let res: i32;
            let mut mod_info = mem::MaybeUninit::<psapi::MODULEINFO>::uninit();

            // request base address and size information about the module handle
            res = psapi::GetModuleInformation(
                processthreadsapi::GetCurrentProcess(),
                handle,
                mod_info.as_mut_ptr().cast(),
                mem::size_of_val(&mod_info) as u32,
            );
            if res == 0 {
                return Err(anyhow::anyhow!("GetModuleInformation failed, handle might be invalid"));
            }

            Ok(
                DllRef {
                    handle,
                    base: mod_info.assume_init().lpBaseOfDll.cast(),
                    size: mod_info.assume_init().SizeOfImage as usize
                }
            )
        }
    }

    /// get a pointer to the end of the module (not a valid address)
    pub fn is_ptr_in_module(&self, ptr: *const u8) -> bool
    {
        unsafe {
            if ptr < self.base || ptr >= self.base.add(self.size) {
                return false
            }
            return true
        }
    }

    /// translate a local module pointer to a remote module's pointer
    pub fn local_ptr_to_remote(&self, local: *const u8, remote_module: &RemoteDllRef) -> Result<usize>
    {
        // just verify it's within limits first
        if !self.is_ptr_in_module(local) {
            return Err(anyhow::anyhow!("Pointer is not within this module"))
        }

        let local_addr = local as usize;
        let local_offset = local_addr - (self.base as usize);

        Ok(remote_module.get_remote_base() + (local_offset as usize))
    }

    /// read a signature string format and convert it into signature slice
    fn signature_from_string(sig: &str) -> anyhow::Result<Vec<SignatureItem>>
    {
        // convert "XX ?? ?? YY ZZ ??" into a signature
        let spl: Result<Vec<SignatureItem>> = sig
            // split on " "
            .split(" ")
            // parse wildcard or hex bytes
            .map(|x| -> Result<SignatureItem> { match x {
                "??" => Ok(Wildcard),
                hex_byte => Ok(Byte(u8::from_str_radix(hex_byte, 16)?))
            }})
            // collect together into a final Result
            .collect();

        // fail if our hex bytes signature parsing failed
        let spl = spl.with_context(|| "Failed parsing signature format")?;

        Ok(spl)
    }

    /// Scan for a function by signature
    pub unsafe fn find_pointer_sig<T>(&self, signature: &str) -> Result<*mut T>
    {
        // parse the string representation of the signature
        let sig = Self::signature_from_string(signature)?;

        // perform the search
        return self.find_pointer(&sig)
    }

    /// Scan for a function by signature
    unsafe fn find_pointer<T>(&self, signature: &[SignatureItem]) -> Result<*mut T>
        where T: Sized
    {
        // current position in the scan
        let mut cur_loc: *const u8 = self.base.cast();

        // the end of the region of memory we're scanning
        let end_mem: *const u8 = cur_loc
            .add(self.size)
            .sub(signature.len())
            .cast();

        // get the first byte of the signature, ensure it's not a wildcard since that's invalid
        if signature.len() <= 1 {
            return Err(anyhow::anyhow!("Signature must be at least 1 byte long"));
        }

        // get the first byte of the signature
        let first_byte_u8: u8 = match &signature[0] {
            SignatureItem::Wildcard => return Err(anyhow::anyhow!("Signature cannot start with a wildcard")),
            SignatureItem::Byte(byt) => byt.clone(),
        };

        let num_sig_bytes = signature.len();
        let mut found;

        loop {
            if cur_loc > end_mem {
                // did not find the signature in the memory range
                break;
            }

            // read the first byte
            let mut mem_byte = cur_loc.read();

            // scan until we find one instance of the byte we care for
            if mem_byte != first_byte_u8 {
                cur_loc = cur_loc.add(1);
                continue;
            }

            found = true;

            // now go through each signature byte and make sure it matches
            for idx in 1..num_sig_bytes {
                match signature.get_unchecked(idx) {
                    // byte we're looking for
                    SignatureItem::Byte(byt) => {
                        // read another byte
                        mem_byte = cur_loc.add(idx).read();

                        if byt.clone() != mem_byte {
                            // not the byte we were looking for
                            found = false;
                            break;
                        }
                    }

                    // skip the entry on wildcard
                    SignatureItem::Wildcard => continue
                }
            }

            if found {
                // we found the signature we wanted!
                return Ok(cur_loc as *mut T);
            } else {
                // try the next location
                cur_loc = cur_loc.add(1);
            }
        }

        // if we fall through to here, we did not find the signature
        return Err(anyhow::anyhow!("Signature not found"));
    }
}

pub struct DllLoader
{}

impl DllLoader
{
    /// add a directory to the default search order
    pub unsafe fn add_dll_directory(dir: &WideCString) -> Result<libloaderapi::DLL_DIRECTORY_COOKIE>
    {
        // enable non-default dll load paths
        let res = libloaderapi::SetDefaultDllDirectories(
            libloaderapi::LOAD_LIBRARY_SEARCH_DEFAULT_DIRS
                | libloaderapi::LOAD_LIBRARY_SEARCH_SYSTEM32
                | libloaderapi::LOAD_LIBRARY_SEARCH_APPLICATION_DIR
                | libloaderapi::LOAD_LIBRARY_SEARCH_USER_DIRS
        );
        if res == 0 {
            return Err(anyhow::anyhow!("SetDefaultDllDirectories failed"));
        }

        // add directory, we don't care about cleaning this up
        let cookie = libloaderapi::AddDllDirectory(dir.as_ptr());
        if cookie.is_null() {
            return Err(anyhow::anyhow!("AddDllDirectory failed"))
        }

        Ok(cookie)
    }

    /// remove a directory from the default search order
    pub unsafe fn remove_dll_directory(cookie: libloaderapi::DLL_DIRECTORY_COOKIE) -> Result<()>
    {
        let res = libloaderapi::RemoveDllDirectory(cookie);
        if res == 0 {
            return Err(anyhow::anyhow!("RemoveDllDirectory failed, cookie was incorrect."));
        }

        Ok(())
    }

    /// load a dll into memory
    pub unsafe fn load_library(path: &WideCString) -> Result<DllRef>
    {
        let handle = libloaderapi::LoadLibraryW(path.as_ptr());
        if handle.is_null() {
            return Err(anyhow::anyhow!("LoadLibraryW failed to load module: {}", Win32ErrorFormatter::error_str()));
        }

        let libref = DllRef::from_handle(handle);

        return libref;
    }
}