use anyhow::Result;
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::winnt::{PROCESS_VM_READ, HANDLE, PROCESS_QUERY_INFORMATION, PROCESS_VM_WRITE, PROCESS_VM_OPERATION};
use crate::loader::{Win32ErrorFormatter, RemoteDllRef, Win32Strings};
use num_derive::ToPrimitive;
use num_traits::ToPrimitive;
use winapi::_core::mem::MaybeUninit;
use winapi::um::psapi::EnumProcessModules;
use std::sync::Arc;
use winapi::um::handleapi::CloseHandle;
use std::ops::Deref;
use winapi::um::memoryapi::ReadProcessMemory;
use winapi::um::tlhelp32::{PROCESSENTRY32W, CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, Process32FirstW, Process32NextW};

pub struct AutoHandle
{
    handle: HANDLE,
}

impl Drop for AutoHandle
{
    fn drop(&mut self)
    {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

impl Deref for AutoHandle {
    type Target = HANDLE;

    fn deref(&self) -> &Self::Target {
        &self.handle
    }
}

impl AutoHandle {
    /// create a new auto handle if it's a valid handle
    fn new(handle: HANDLE) -> Result<AutoHandle>
    {
        if handle.is_null() {
            return Err(anyhow::anyhow!("Null handle passed to AutoHandle::new"))
        }

        Ok(AutoHandle
        {
            handle
        })
    }
}

#[derive(Clone)]
pub struct ProcessHandle
{
    // the raw process handle
    handle: Arc<AutoHandle>,
}

pub struct ProcessMemoryReader
{
    // raw process handle
    handle: ProcessHandle,

    // the current base address to read from
    base: usize,
}

impl std::io::Read for ProcessMemoryReader
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize>
    {
        let res = self.handle.read_memory(self.base as usize, buf);
        if res.is_err() {
            println!("{:?}", res.unwrap_err());
            return Ok(0)
        }

        return Ok(res.unwrap() as usize)
    }
}

#[repr(u32)]
#[derive(ToPrimitive)]
pub enum ProcessPermission {
    ReadMemory = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ) as u32,
    WriteMemory = (PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION) as u32,
}

impl ProcessHandle
{
    pub fn open_name(target_name: &str, permissions: &[ProcessPermission]) -> Result<ProcessHandle>
    {
        unsafe {
            // allocate space for a process entry struct on the stack
            let mut entry: MaybeUninit<PROCESSENTRY32W> = MaybeUninit::uninit();
            entry.as_mut_ptr().as_mut().unwrap().dwSize = std::mem::size_of_val(&entry) as u32;

            let a = entry.assume_init().dwSize;

            // open a snapshot handle (closes automatically on Drop)
            let snaphandle = AutoHandle::new(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))?;

            // iterate each process looking for the name
            if Process32FirstW(*snaphandle, entry.as_mut_ptr()) != 0
            {
                while Process32NextW(*snaphandle, entry.as_mut_ptr()) != 0
                {
                    // convert to utf8
                    let name = Win32Strings::from_utf16(entry.assume_init().szExeFile.as_ptr());

                    // if it's the name we want
                    if name == target_name
                    {
                        // open a handle and return it
                        return ProcessHandle::open_pid(entry.assume_init().th32ProcessID, permissions);
                    }
                }

                // otherwise we didn't find it
                return Err(anyhow::anyhow!("Process {} not found", target_name))
            }

            // otherwise we didn't find it
            Err(anyhow::anyhow!("Failed Process32FirstW: {}", Win32ErrorFormatter::error_str()))
        }
    }
    /// open a process by pid
    pub fn open_pid(pid: u32, permissions: &[ProcessPermission]) -> Result<Self>
    {
        // calculate the flags value for desired access
        let flags: u32 = permissions
            .iter()
            .fold(0,
                  |acc, x| (acc | ToPrimitive::to_u32(x).unwrap())
            );

        unsafe {
            // open the process handle
            let handle = OpenProcess(flags, 0, pid);
            if handle.is_null() {
                return Err(anyhow::anyhow!("OpenProcess failed: {}", Win32ErrorFormatter::error_str()));
            }

            return Ok(ProcessHandle{
                handle: Arc::new(AutoHandle { handle })
            })
        }
    }

    /// get all modules in the process
    pub fn get_modules(&self) -> Result<Vec<RemoteDllRef>>
    {
        unsafe {
            let mut modules: MaybeUninit<[HANDLE; 1024]> = MaybeUninit::uninit();
            let mut needed: MaybeUninit<u32> = MaybeUninit::uninit();

            // enumerate the modules in the remote process
            let res = EnumProcessModules(
                **self.handle,
                modules.as_mut_ptr().cast(),
                std::mem::size_of_val(&modules) as u32,
                needed.as_mut_ptr()
            );
            if res == 0 {
                return Err(anyhow::anyhow!("EnumProcessModules failed"));
            }

            // calculate the number of modules that was returned
            let num_modules = needed.assume_init() / std::mem::size_of::<HANDLE>() as u32;

            // convert these handles to DllRef
            let out_modules: Vec<RemoteDllRef> = (0..num_modules)
                .map(|x|
                    RemoteDllRef::from_handle(modules.assume_init()[x as usize].cast(), self.handle.clone())
                )
                .collect();

            Ok(out_modules)
        }
    }

    /// read memory from the remote process into out_mem
    pub fn read_memory(&self, remote_ptr: usize, out_mem: &mut [u8]) -> Result<u32>
    {
        unsafe {
            let mut amount_read: MaybeUninit<u32> = MaybeUninit::uninit();

            let success = ReadProcessMemory(
                **self.handle,
                remote_ptr as _,
                out_mem.as_mut_ptr() as _,
                out_mem.len(),
                amount_read.as_mut_ptr() as _
            );
            if success == 0
            {
                return Err(anyhow::anyhow!("ReadProcessMemory failed: {}", Win32ErrorFormatter::error_str()))
            }

            return Ok(amount_read.assume_init())
        }
    }

    /// get a reader to the memory of the remote process
    pub fn get_memory_reader(&self, remote_ptr: usize) -> ProcessMemoryReader
    {
        ProcessMemoryReader
        {
            handle: self.clone(),
            base: remote_ptr,
        }
    }
}

#[test]
fn process_open()
{
    let proc = ProcessHandle::open_pid(20484, &[ProcessPermission::ReadMemory]).unwrap();
    let modules = proc.get_modules().unwrap();

    modules
        .iter()
        .for_each(|r| println!("{}", r.get_name().unwrap()));
}

#[test]
fn process_open_name()
{
    let proc = ProcessHandle::open_name("notepad.exe", &[ProcessPermission::ReadMemory]).unwrap();
    let modules = proc.get_modules().unwrap();

    modules
        .iter()
        .for_each(|r| println!("{}", r.get_name().unwrap()));
}