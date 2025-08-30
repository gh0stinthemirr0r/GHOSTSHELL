use std::env;
use std::path::PathBuf;
use std::fs;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    
    // Tell Cargo about our custom cfg
    println!("cargo:rustc-check-cfg=cfg(npcap_available)");
    println!("cargo:rustc-check-cfg=cfg(no_pcap)");
    
    // Handle packet capture on Windows
    if cfg!(target_os = "windows") {
        let npcap_detected = detect_npcap();
        
        if npcap_detected {
            println!("cargo:rustc-cfg=npcap_available");
            setup_npcap_linking();
        } else {
            println!("cargo:rustc-cfg=no_pcap");
            println!("cargo:warning=Npcap not detected. PCAP capture will be disabled. Install Npcap to enable packet capture functionality.");
        }
        
        // Always link Windows socket libraries for raw socket fallback and other network operations
        println!("cargo:rustc-link-lib=ws2_32");
        println!("cargo:rustc-link-lib=iphlpapi");
    } else {
        // On non-Windows platforms, disable pcap for now
        println!("cargo:rustc-cfg=no_pcap");
        println!("cargo:warning=Packet capture is currently only supported on Windows with Npcap.");
    }
}

/// Detect if Npcap is properly installed on the system
fn detect_npcap() -> bool {
    // Method 1: Check for Npcap service in registry (most reliable)
    if check_npcap_service() {
        println!("cargo:warning=Npcap service detected in registry");
        return true;
    }
    
    // Method 2: Check for Npcap installation registry keys
    if check_npcap_registry() {
        println!("cargo:warning=Npcap installation detected in registry");
        return true;
    }
    
    // Method 3: Check for Npcap DLL files
    if check_npcap_files() {
        println!("cargo:warning=Npcap DLL files detected");
        return true;
    }
    
    println!("cargo:warning=Npcap not detected using any method");
    false
}

/// Check for Npcap service in Windows registry
fn check_npcap_service() -> bool {
    use std::process::Command;
    
    // Use reg.exe to check for Npcap service
    let output = Command::new("reg")
        .args(&[
            "query", 
            "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\npcap",
            "/ve"
        ])
        .output();
    
    match output {
        Ok(result) => result.status.success(),
        Err(_) => false,
    }
}

/// Check for Npcap installation in Windows registry
fn check_npcap_registry() -> bool {
    use std::process::Command;
    
    // Check native registry location
    let native_check = Command::new("reg")
        .args(&[
            "query",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\Npcap",
            "/ve"
        ])
        .output();
    
    if let Ok(result) = native_check {
        if result.status.success() {
            return true;
        }
    }
    
    // Check WOW6432Node for 32-bit installations on 64-bit systems
    let wow_check = Command::new("reg")
        .args(&[
            "query",
            "HKEY_LOCAL_MACHINE\\SOFTWARE\\WOW6432Node\\Npcap",
            "/ve"
        ])
        .output();
    
    if let Ok(result) = wow_check {
        if result.status.success() {
            return true;
        }
    }
    
    false
}

/// Check for Npcap DLL files in expected locations
fn check_npcap_files() -> bool {
    let npcap_paths = vec![
        "C:\\Windows\\System32\\Npcap\\wpcap.dll",
        "C:\\Windows\\System32\\Npcap\\Packet.dll",
        "C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll",
        "C:\\Windows\\SysWOW64\\Npcap\\Packet.dll",
    ];
    
    // Check if at least one pair of DLLs exists
    let system32_exists = PathBuf::from("C:\\Windows\\System32\\Npcap\\wpcap.dll").exists() &&
                         PathBuf::from("C:\\Windows\\System32\\Npcap\\Packet.dll").exists();
    
    let syswow64_exists = PathBuf::from("C:\\Windows\\SysWOW64\\Npcap\\wpcap.dll").exists() &&
                         PathBuf::from("C:\\Windows\\SysWOW64\\Npcap\\Packet.dll").exists();
    
    system32_exists || syswow64_exists
}

/// Set up linking for Npcap libraries
fn setup_npcap_linking() {
    // Check for bundled libraries first (in project lib directory)
    let project_lib_dir = PathBuf::from("../lib");
    if project_lib_dir.exists() {
        let wpcap_lib = project_lib_dir.join("wpcap.lib");
        let packet_lib = project_lib_dir.join("Packet.lib");
        
        if wpcap_lib.exists() && packet_lib.exists() {
            // Copy bundled libraries to OUT_DIR so linker can find them
            let out_dir = env::var("OUT_DIR").unwrap();
            let out_lib_dir = PathBuf::from(&out_dir).join("npcap_libs");
            fs::create_dir_all(&out_lib_dir).ok();
            
            let dest_wpcap = out_lib_dir.join("wpcap.lib");
            let dest_packet = out_lib_dir.join("Packet.lib");
            
            if fs::copy(&wpcap_lib, &dest_wpcap).is_ok() && fs::copy(&packet_lib, &dest_packet).is_ok() {
                println!("cargo:rustc-link-search=native={}", out_lib_dir.display());
                println!("cargo:rustc-link-lib=wpcap");
                println!("cargo:rustc-link-lib=Packet");
                println!("cargo:warning=Using bundled Npcap libraries from: {} (copied to {})", project_lib_dir.display(), out_lib_dir.display());
                return;
            }
        }
    }
    
    // Try system installation paths
    let npcap_paths = vec![
        "C:\\Windows\\System32\\Npcap",
        "C:\\Windows\\SysWOW64\\Npcap",
        "C:\\Program Files\\Npcap",
        "C:\\Program Files (x86)\\Npcap",
    ];
    
    for path in npcap_paths {
        let path_buf = PathBuf::from(path);
        if path_buf.exists() {
            println!("cargo:rustc-link-search=native={}", path_buf.display());
            println!("cargo:rustc-link-lib=wpcap");
            println!("cargo:rustc-link-lib=Packet");
            println!("cargo:warning=Using system Npcap libraries from: {}", path);
            return;
        }
    }
    
    println!("cargo:warning=Npcap detected but library path not found. PCAP functionality may not work correctly.");
}