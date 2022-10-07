use std::os::windows::prelude::*;
use std::process::exit;
use std::path::Path;

use winapi::shared::minwindef::BOOL;
use winapi::um::memoryapi::{VirtualAllocEx};
use winapi::um::processthreadsapi::{GetExitCodeThread, OpenProcess};
use winapi::um::winnt::{
    HANDLE, MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, PAGE_READWRITE, PROCESS_ALL_ACCESS,
};

use eframe::egui;
use egui::Vec2;

fn main() { 
    let mut options = eframe::NativeOptions::default();
    //Set options.resizable to false to disable resizing
    options.resizable = false;
    options.initial_window_size = Option::from(Vec2::new(340 as f32, 80 as f32));

    eframe::run_native("Kostek Injector",  options, Box::new(|_cc| Box::new(App::default())));
}

struct App {
    fileLoc: String,
    inject: bool,
    pid: String,
}

impl Default for App {
    fn default() -> Self {
        Self {
            fileLoc: "".to_owned(),
            inject: false,
            pid: "".to_owned(),
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label("Path");
                ui.text_edit_singleline(&mut self.fileLoc);
            });
            ui.horizontal(|ui| {
                ui.label("PID  ");
                ui.text_edit_singleline(&mut self.pid);
            });
            ui.horizontal(|ui| {
                if ui.button("Inject").clicked() {
                    self.inject = true;
                }
            })
        });

        if (self.inject == true)
        {
            //Get path to the DLL
            let path = Path::new(&self.fileLoc);

            //Verify if the path exists
            if !path.exists()
            {
                exit(1);
            }

            //Open Process using winapi
            let pid = self.pid.parse::<u32>().unwrap();
            let handle = unsafe { OpenProcess(PROCESS_ALL_ACCESS, 0, pid) };

            println!("PID: {}", pid);
            println!("path: {}", path.display());

            if handle.is_null()
            {
                exit(2);
            }

            //Get size of the DLL, it should be usize
            let dll_size = path.metadata().unwrap().len() as usize;

            //Get the DLL path as a C-String
            let dll_path = path.as_os_str().encode_wide().chain(Some(0).into_iter()).collect::<Vec<_>>();


            //Allocate memory for the DLL path
            let alloc = unsafe { winapi::um::memoryapi::VirtualAllocEx(handle, std::ptr::null_mut(), 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) };

            if alloc.is_null()
            {
                exit(3);
            }
            
            //Write the DLL path to the allocated memory using WriteProcessMemory
            let mut bytes_written: usize = 0;
            let write = unsafe { winapi::um::memoryapi::WriteProcessMemory(handle, alloc, dll_path.as_ptr() as *const _, dll_size, &mut bytes_written) };
            /*
            if write == 0
            {
                exit(4);
            }
            */
            
            //GetProcAddress and store it as a pointer
            let loadlib = unsafe { winapi::um::libloaderapi::GetProcAddress(winapi::um::libloaderapi::GetModuleHandleA("kernel32.dll".as_ptr() as *const _), "LoadLibraryW".as_ptr() as *const _) };

            //Inject remote thread into the target process, converting "loadlib" to a function pointer
            let thread = unsafe { winapi::um::processthreadsapi::CreateRemoteThread(handle, std::ptr::null_mut(), 0, Some(std::mem::transmute::<_, extern "system" fn(_) -> _>(loadlib)), alloc, 0, std::ptr::null_mut()) };
            if thread == std::ptr::null_mut()
            {
                exit(5);
            }

            exit(0);
        }
    }
}