use ldrcrawler::{get_func_address, get_module_handle, hide_module, WinExecFunc};
use std::mem::transmute;

fn main() {
    match get_module_handle("kernel32.dll") {
        Some(kernel32_base) => {
            println!("[+] get_module_handle(kernel32.dll) = {:x}", kernel32_base);
            
            let func_addr = get_func_address(kernel32_base, "WinExec");
            if func_addr != 0 {
                let ptr_winexec: WinExecFunc = unsafe { transmute(func_addr) };
                println!("[+] get_func_address(WinExec) = {:?}", ptr_winexec);
                let _ = ptr_winexec("calc\0".as_ptr() as *const u8, 5);
            } else {
                eprintln!("[-] Failed to find WinExec");
            }
            
            hide_module("apphelp.dll");
            println!("[+] Module hidden successfully");
        }
        None => {
            eprintln!("[-] Failed to find kernel32.dll");
        }
    }
}
