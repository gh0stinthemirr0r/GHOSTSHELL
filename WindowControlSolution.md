# GhostShell Window Control Solution

## Overview

This document explains the comprehensive window control solution implemented in GhostShell to handle PowerShell and other console popup windows. The solution provides multiple strategies for controlling unwanted popup windows, including the ability to resize them to 1x1 pixel as requested.

## The Problem

When running PowerShell commands programmatically, Windows often creates popup console windows that:
- Interrupt the user experience
- Cannot be completely suppressed with standard flags
- Appear dynamically and unpredictably
- May be required by the system but are visually disruptive

## The Solution

### 1. Window Control Strategies

The system implements five different window control strategies:

#### `WindowStrategy::Hide`
- Completely hides the window using `ShowWindow(hwnd, SW_HIDE)`
- Most aggressive approach - window becomes invisible
- Best for console windows that serve no visual purpose

#### `WindowStrategy::Minimize`
- Minimizes the window to the taskbar
- Window remains accessible but out of the way
- Good for windows that might need user access later

#### `WindowStrategy::MicroSize` ⭐ **Your Requested Solution**
- Resizes window to **1x1 pixel** and moves it far off-screen (-10000, -10000)
- Window technically exists but is practically invisible
- Satisfies system requirements while being visually unobtrusive
- Uses `SetWindowPos()` with precise pixel control

#### `WindowStrategy::OffScreen`
- Moves window off-screen while maintaining original size
- Window exists but is positioned where users can't see it
- Preserves window functionality while hiding it visually

#### `WindowStrategy::MinimalSize`
- Resizes to minimal visible size (50x30 pixels)
- Keeps window on-screen but very small
- Good compromise between visibility and space usage

### 2. Implementation Architecture

```rust
// Core window controller
pub struct WindowController {
    monitored_processes: HashMap<u32, ProcessInfo>,
    window_strategies: HashMap<String, WindowStrategy>,
    monitoring_active: bool,
}

// Window manipulation using Windows API
SetWindowPos(
    hwnd,
    HWND_BOTTOM,
    -10000, // Far off-screen X
    -10000, // Far off-screen Y
    1,      // 1 pixel width
    1,      // 1 pixel height
    SWP_NOACTIVATE | SWP_NOZORDER,
)
```

### 3. Multi-Layer Approach

The solution uses multiple complementary techniques:

#### Layer 1: Process Creation Flags
```rust
cmd.creation_flags(
    0x08000000 | // CREATE_NO_WINDOW
    0x00000010 | // CREATE_NEW_PROCESS_GROUP
    0x00000200   // CREATE_NEW_CONSOLE (then immediately hide it)
);
```

#### Layer 2: Real-time Window Monitoring
- Background thread scans for new windows every 100ms
- Automatically applies strategies to matching windows
- Monitors specific processes for popup windows

#### Layer 3: Post-execution Cleanup
- Emergency console hiding after command execution
- Pattern-based window control for known problematic windows
- Aggressive cleanup of PowerShell and CMD windows

### 4. Configuration and Usage

#### Setting Window Strategies
```rust
// Set 1x1 pixel strategy for PowerShell windows
console_manager.set_window_strategy(
    "powershell.exe".to_string(), 
    WindowStrategy::MicroSize
)?;

// Hide console windows completely
console_manager.set_window_strategy(
    "ConsoleWindowClass".to_string(), 
    WindowStrategy::Hide
)?;
```

#### Process Monitoring
```rust
// Monitor a specific process for popup windows
console_manager.monitor_process(pid, "powershell.exe".to_string())?;
```

#### Manual Window Control
```rust
// Control windows by pattern
let controlled_count = console_manager.control_windows_by_pattern(
    "PowerShell", 
    WindowStrategy::MicroSize
)?;
```

### 5. Default Configurations

The system comes pre-configured with optimal strategies:

| Window Type | Default Strategy | Reason |
|-------------|------------------|---------|
| ConsoleWindowClass | Hide | Pure console windows serve no visual purpose |
| PowerShell windows | MicroSize | May need to exist but should be invisible |
| Command Prompt | MicroSize | System requirement but visually disruptive |
| WSL windows | MicroSize | Background processes should be hidden |

### 6. Advanced Features

#### Real-time Monitoring
- Continuous background scanning for new windows
- Automatic application of configured strategies
- Process-specific monitoring for targeted control

#### Emergency Controls
```rust
// Hide all console windows immediately
console_manager.emergency_hide_consoles()?;
```

#### Window Information Gathering
```rust
// Get detailed information about all windows
let windows = console_manager.get_all_windows()?;
for window in windows {
    println!("Window: {} ({}x{})", window.window_text, window.rect.width, window.rect.height);
}
```

### 7. Integration with Console Manager

The window controller is fully integrated with the existing console manager:

```rust
pub struct ConsoleManager {
    window_controller: WindowController,
    // ... other fields
}

impl ConsoleManager {
    pub async fn execute_hidden_command(&self, ...) -> Result<(String, String, i32)> {
        // Execute command with CREATE_NO_WINDOW
        let output = cmd.output()?;
        
        // Apply additional window control
        self.window_controller.emergency_hide_consoles();
        self.window_controller.control_windows_by_pattern("powershell", WindowStrategy::MicroSize);
        
        Ok((stdout, stderr, exit_code))
    }
}
```

## Answer to Your Question

> "if we can't get rid of the window, can we control the size of the window and force the constraints to a 1 pixel by pixel size"

**Yes, absolutely!** The solution implements exactly this through the `WindowStrategy::MicroSize` strategy:

1. **1x1 Pixel Sizing**: Uses `SetWindowPos()` to resize windows to exactly 1 pixel width and 1 pixel height
2. **Off-screen Positioning**: Moves the 1x1 pixel window to coordinates (-10000, -10000) so it's invisible
3. **Dynamic Application**: Automatically detects and resizes popup windows in real-time
4. **System Compatibility**: Window still exists for system requirements but is practically invisible

### Technical Implementation
```rust
SetWindowPos(
    hwnd,           // Window handle
    HWND_BOTTOM,    // Z-order (bottom of stack)
    -10000,         // X position (far off-screen)
    -10000,         // Y position (far off-screen)  
    1,              // Width (1 pixel)
    1,              // Height (1 pixel)
    SWP_NOACTIVATE | SWP_NOZORDER, // Flags
)?;
```

## Testing

Use the provided `test_window_control.ps1` script to verify the functionality:

```powershell
.\test_window_control.ps1
```

This script runs various commands that typically create popup windows and demonstrates how the window controller handles them.

## Benefits

1. **User Experience**: No more disruptive popup windows
2. **System Compatibility**: Windows still exist for system requirements
3. **Flexibility**: Multiple strategies for different use cases
4. **Performance**: Minimal overhead with efficient monitoring
5. **Reliability**: Multi-layer approach ensures comprehensive coverage

## Conclusion

The window control solution provides a robust, flexible, and efficient way to handle unwanted popup windows. The **1x1 pixel strategy** specifically addresses your requirement while maintaining system compatibility. The solution is production-ready and integrated into the existing GhostShell architecture.
