use std::arch::asm;
use std::ffi::c_void;
use std::ffi::CStr;
use std::os::raw::c_char;
#[cfg(target_arch = "x86")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS32;
#[cfg(target_arch = "x86_64")]
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::IMAGE_DOS_HEADER;
use windows::Win32::System::SystemServices::IMAGE_EXPORT_DIRECTORY;

#[cfg(target_arch = "x86")]
pub type WinExecFunc = extern "stdcall" fn(LPCSTR: *const u8, UINT: u32) -> u32;
#[cfg(target_arch = "x86_64")]
pub type WinExecFunc = extern "system" fn(LPCSTR: *const u8, UINT: u32) -> u32;

#[inline]
#[cfg(target_arch = "x86_64")]
fn __readgsqword(offset: u32) -> u64 {
    let out: u64;
    unsafe {
        asm!(
            "mov {1:r}, gs:[{0:e}]", in(reg) offset, out(reg) out,
        );
    }
    out
}

#[inline]
#[cfg(target_arch = "x86")]
fn __readfsword(offset: u32) -> u32 {
    let out: u32;
    unsafe {
        asm!(
            "mov {1:e}, fs:[{0:e}]", in(reg) offset, out(reg) out,
        );
    }
    out
}

#[cfg(target_arch = "x86_64")]
const ENTRY_OFFSET: usize = 16; //-16 is used instead of the CONTAINING_RECORD macro.
#[cfg(target_arch = "x86")]
const ENTRY_OFFSET: usize = 8; //-8 is used instead of the CONTAINING_RECORD macro.

/// Extract DLL name from LdrDataTableEntry, normalized to lowercase
unsafe fn get_dll_name(entry: *const LdrDataTableEntry) -> String {
    let dll_name_slice = std::slice::from_raw_parts(
        (*entry).base_dll_name.buffer,
        ((*entry).base_dll_name.length / 2) as usize, // /2 because of unicode
    );
    String::from_utf16_lossy(dll_name_slice).to_lowercase()
}

/// Normalize a library name for comparison (lowercase)
fn normalize_lib_name(lib_name: &str) -> String {
    lib_name.to_lowercase()
}

/// Unlink a list entry from a doubly-linked list
unsafe fn unlink_list_entry(list_entry: *const ListEntry) {
    let prev = (*list_entry).blink;
    let next = (*list_entry).flink;
    if !prev.is_null() {
        (*prev).flink = next;
    }
    if !next.is_null() {
        (*next).blink = prev;
    }
}

/// Iterate through all loaded modules and call callback
unsafe fn iterate_modules<F>(mut callback: F)
where
    F: FnMut(*const LdrDataTableEntry) -> bool,
{
    #[cfg(target_arch = "x86_64")]
    let peb = __readgsqword(0x60) as *const Peb;
    #[cfg(target_arch = "x86")]
    let peb = __readfsword(0x30) as *const Peb;

    let header = (*(*peb).ldr).in_memory_order_module_list;

    let mut curr = header.flink;
    curr = (*curr).flink;

    while curr != header.flink {
        let data = (curr as usize - ENTRY_OFFSET) as *const LdrDataTableEntry;
        if !callback(data) {
            break;
        }
        curr = (*curr).flink;
    }
}

/// Get the base address of a loaded module by name
/// 
/// # Arguments
/// * `lib_name` - The name of the library (e.g., "kernel32.dll")
/// 
/// # Returns
/// `Some(base_address)` if the module is found, `None` otherwise
pub fn get_module_handle(lib_name: &str) -> Option<usize> {
    let lib_name = normalize_lib_name(lib_name);
    let mut result = None;
    unsafe {
        iterate_modules(|entry| {
            let dll_name = get_dll_name(entry);
            if dll_name == lib_name {
                result = Some((*entry).dll_base as usize);
                return false; // Stop iteration
            }
            true // Continue iteration
        });
    }
    result
}

/// Hide a module from enumeration by unlinking it from all module lists
/// 
/// # Arguments
/// * `lib_name` - The name of the library to hide (e.g., "apphelp.dll")
pub fn hide_module(lib_name: &str) {
    let lib_name = normalize_lib_name(lib_name);
    unsafe {
        iterate_modules(|entry| {
            let dll_name = get_dll_name(entry);
            if dll_name == lib_name {
                // Unlink from all three lists
                unlink_list_entry(&(*entry).in_memory_order_links);
                unlink_list_entry(&(*entry).in_load_order_links);
                unlink_list_entry(&(*entry).in_initialization_order_links);
                return false; // Stop iteration
            }
            true // Continue iteration
        });
    }
}

/// Get the address of an exported function from a module
/// 
/// # Arguments
/// * `module_base` - The base address of the loaded module
/// * `func_name` - The name of the exported function
/// 
/// # Returns
/// The function address if found, 0 otherwise
pub fn get_func_address(module_base: usize, func_name: &str) -> usize {
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    #[cfg(target_arch = "x86_64")]
    let nt_headers =
        unsafe { (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64 };
    #[cfg(target_arch = "x86")]
    let nt_headers =
        unsafe { (module_base + (*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS32 };
    
    let optional_headers = unsafe { &(*nt_headers).OptionalHeader };
    let export_table_data = optional_headers.DataDirectory[0];

    let export_table =
        (module_base + export_table_data.VirtualAddress as usize) as *const IMAGE_EXPORT_DIRECTORY;
    
    unsafe {
        let export_dir = &*export_table;
        let array_of_functions = module_base + export_dir.AddressOfFunctions as usize;
        let array_of_names = module_base + export_dir.AddressOfNames as usize;
        let array_of_names_ordinals = module_base + export_dir.AddressOfNameOrdinals as usize;

        for i in 0..export_dir.NumberOfFunctions {
            let fn_name_address = module_base + *((array_of_names + (i * 4) as usize) as *const u32) as usize;
            let fn_name = match CStr::from_ptr(fn_name_address as *const c_char).to_str() {
                Ok(cstr) => cstr,
                Err(_) => continue,
            };
            
            if fn_name == func_name {
                let num_curr_api_ordinal = *((array_of_names_ordinals + (i * 2) as usize) as *const u16) as usize;
                println!("[+] Found ordinal {:4x} - {}", num_curr_api_ordinal + 1, fn_name);
                
                return module_base + *((array_of_functions + (num_curr_api_ordinal * 4)) as *const u32) as usize;
            }
        }
    }
    
    0
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *const u16,
}

#[repr(C)]
union HashLinksOrSectionPointer {
    hash_links: ListEntry,
    section_pointer: *mut c_void,
}

#[repr(C)]
union TimeDateStampOrLoadedImports {
    time_date_stamp: usize,
    loaded_imports: *mut c_void,
}

#[repr(C)]
struct LdrDataTableEntry {
    in_load_order_links: ListEntry,
    in_memory_order_links: ListEntry,
    in_initialization_order_links: ListEntry,
    dll_base: *mut c_void,
    entry_point: *mut c_void,
    size_of_image: usize,
    full_dll_name: UnicodeString,
    base_dll_name: UnicodeString,
    flags: usize,
    load_count: u16,
    tls_index: u16,
    hash_links_or_section_pointer: HashLinksOrSectionPointer, // Union
    checksum: usize,
    time_date_stamp_or_loaded_imports: TimeDateStampOrLoadedImports, // Union
    entry_point_activation_context: *mut c_void,
    patch_information: *mut c_void,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct ListEntry {
    flink: *mut ListEntry,
    blink: *mut ListEntry,
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct PebLdrData {
    length: usize,
    initialized: u8,
    ss_handle: *mut c_void,
    in_load_order_module_list: ListEntry,
    in_memory_order_module_list: ListEntry,
    in_initialization_order_module_list: ListEntry,
    entry_in_progress: *mut c_void,
}

#[repr(C)]
struct Peb {
    inherited_address_space: u8,
    read_image_file_exec_options: u8,
    being_debugged: u8,
    bit_field: u8,
    mutant: *mut c_void,
    image_base_address: *mut c_void,
    ldr: *mut PebLdrData,
    process_parameters: usize,
    sub_system_data: *mut c_void,
    process_heap: *mut c_void,
    fast_peb_lock: *mut c_void,
    atl_thunk_slist_ptr: *mut c_void,
    ifeo_key: *mut c_void,
    cross_process_flags: usize,
    user_shared_info_ptr: *mut c_void,
    system_reserved: usize,
    atl_thunk_slist_ptr32: usize,
    api_set_map: *mut c_void,
}
