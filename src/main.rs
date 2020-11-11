use anyhow::Result;
use widestring::WideCString;

mod loader;
use loader::*;

use SignatureItem::{Byte, Wildcard};
use std::io::Read;
use std::path::{Path, PathBuf};

extern crate pretty_env_logger;

use serde::{Serialize, Deserialize};

use app_dirs::*;

const APP_INFO: AppInfo = AppInfo {name: "se-client", author: "Gbps" };

#[derive(Serialize, Deserialize)]
struct CsgoValues
{
    host_version: u32,
    send_table_crc: u32,
}

// runs the crcgrab.exe application to grab the g_SendTableCRC value from a real CS:GO game.
struct SendTableCRC
{
}

impl SendTableCRC
{
    /// get the path to the local cache
    fn get_store_path(host_version: u32) -> anyhow::Result<PathBuf>
    {
        let app_path = app_dirs::app_root(AppDataType::UserConfig, &APP_INFO)?;

        let store = app_path
            .join(format!("{}.json", host_version));

        return Ok(store);
    }

    /// write the local cached value
    fn write_cached_value(values: &CsgoValues) -> anyhow::Result<()> {
        let store = Self::get_store_path(values.host_version)?;

        // write out the cached value
        std::fs::write(store, serde_json::to_string_pretty(values)?)?;

        Ok(())
    }
}

fn add_dll_directory(base_dir: &Path, rel_dir: &str) -> Result<()>
{
    // form the target path
    let bin_path = base_dir.join(rel_dir).canonicalize()?;

    log::info!("Adding DLL directory: {}", bin_path.to_string_lossy());

    // convert to wide string
    let dll_dir = WideCString::from_str(bin_path.to_string_lossy())?;

    unsafe
    {
        // add the directory
        DllLoader::add_dll_directory(&dll_dir)?;
    }

    Ok(())
}

unsafe fn load_engine_dll(game_dir: &Path) -> Result<DllRef>
{
    log::trace!("Adding DLL directories...");

    // add the game bin paths so we can load the target dll
    add_dll_directory(game_dir, "bin/")?;
    add_dll_directory(game_dir, "csgo/bin/")?;

    log::trace!("Loading engine.dll...");

    // load engine.dll into our local process
    let dll = DllLoader::load_library(&WideCString::from_str("engine.dll")?)?;

    Ok(dll)
}

unsafe fn read_remote_dword(
    name: &'static str,
    process: &ProcessHandle,
    local_dll: &DllRef,
    remote_dll: &RemoteDllRef,
    signature: &str,
    offset_to_address: usize
) -> Result<u32>
{
    // find the signature in our local dll
    let sig: *mut u8 = local_dll.find_pointer_sig(signature)?;
    log::info!("{}: Found local signature {:p}", name, sig);

    // read the pointer value inside the instruction
    let local_addr: *const *const u8 = sig.add(offset_to_address).cast();
    let local_addr: *const u8 = local_addr.read();
    log::info!("{}: Local address {:p}", name, local_addr);

    // remap the pointer
    let remapped_ptr = local_dll.local_ptr_to_remote(local_addr, remote_dll)?;
    log::info!("{}: Remapped local pointer into remote address space {:p}", name, remapped_ptr as *const u8);

    let mut remote_reader = process.get_memory_reader(remapped_ptr);

    // read 4 bytes and convert to u32
    let mut val: [u8; 4] = Default::default();
    remote_reader.read_exact(&mut val)?;
    let val = u32::from_le_bytes(val);

    log::info!("{}: Remote value: {:x}", name, val);

    Ok(val)
}

unsafe fn read_send_table_crc(dll: DllRef) -> Result<CsgoValues>
{
    log::info!("Opening csgo.exe...");
    let csgo = ProcessHandle::open_name("csgo.exe", &[ProcessPermission::ReadMemory])?;

    log::info!("Finding engine.dll in remote process..");
    let remotedll = csgo
        .get_modules()?
        .into_iter()
        .find(|x| x.get_name().unwrap() == "engine.dll")
        .ok_or(anyhow::anyhow!("DLL was not loaded in the process"))?;

    log::info!("Found engine.dll. engine.dll base: {:p}", remotedll.get_remote_base() as *const u8);

    let send_table_crc = read_remote_dword(
        "g_SendTableCRC",
        &csgo,
        &dll,
        &remotedll,
        "F7 D0 A3 ?? ?? ?? ?? FF 15 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8B C8 8B 10 FF",
        3
    )?;

    let host_version = read_remote_dword(
        "host_version",
        &csgo,
        &dll,
        &remotedll,
        "55 8B EC 8B 55 0C 56 8B 35 ?? ?? ?? ?? 3B D6 74 38",
        9
    )?;

    Ok(CsgoValues
    {
        host_version,
        send_table_crc
    })
}

fn do_main() -> Result<()>
{
    let lib = unsafe { load_engine_dll(Path::new("D:/Steam/steamapps/common/Counter-Strike Global Offensive/")) };
    let dll = lib.unwrap_or_else(|e| panic!("Failed to load client dll: {:?}", e));

    log::trace!("Searching for signature...");

    let value = unsafe {read_send_table_crc(dll)}?;
    log::info!("Successfully read values for host version {}", value.host_version);

    log::info!("g_SendTableCRC: 0x{:x}", value.send_table_crc);

    SendTableCRC::write_cached_value(&value)?;

    Ok(())
}

fn main()
{
    pretty_env_logger::init();

    let res = do_main();
    if res.is_err()
    {
        log::error!("main failed \"{}\", exiting...", res.unwrap_err());
    } else {
        log::info!("main succeeded, exiting...");
    }

    log::info!("Caching value to file...");
}
