<script lang="ts">
  // Only import essential components that are always needed
  import Sidebar from '$lib/components/Sidebar.svelte';
  import TopBar from '$lib/components/TopBar.svelte';
  import CommandPalette from '$lib/components/CommandPalette.svelte';
  import NotificationContainer from '$lib/components/NotificationContainer.svelte';
  import ThemeManagerV2 from '$lib/components/ThemeManagerV2.svelte';
  import FontSelector from '$lib/components/FontSelector.svelte';
  import AccessibilitySettings from '$lib/components/AccessibilitySettings.svelte';
  import NavigationSettings from '$lib/components/NavigationSettings.svelte';
  import { commandPaletteStore } from '$lib/stores/commandPalette';
  import { notificationsStore, clearAllNotifications, markAllAsRead, getUnreadCount, type Notification } from '$lib/stores/notifications';
  import { settingsStore } from '$lib/stores/settings';
  import { onMount, onDestroy } from 'svelte';
  import { Activity, X } from 'lucide-svelte';
  import { invoke } from '@tauri-apps/api/tauri';
  
  // Lazy loading for heavy components
  let loadedComponents: Record<string, any> = {};
  
  // Component loading map
  const componentMap: Record<string, () => Promise<any>> = {
    // Sessions
    'terminal': () => import('$lib/components/TerminalSimple.svelte'),
    'ghostssh': () => import('$lib/components/SshClient.svelte'),
    'ghostbrowse': () => import('$lib/components/BrowserWindow.svelte'),
    
    // Core Modules
    'ghostvault': () => import('$lib/components/GhostVault.svelte'),
    'security': () => import('$lib/components/SecurityPolicy.svelte'),
    'topology': () => import('$lib/components/NetworkTopology.svelte'),
    'ghostvpn': () => import('$lib/components/VpnClient.svelte'),
    'ghostai': () => import('$lib/components/AiAssistant.svelte'),
    
    // Tools
    'layers': () => import('$lib/components/LayersTool.svelte'),
    'surveyor': () => import('$lib/components/SurveyorTool.svelte'),
    'pcap': () => import('$lib/components/PcapStudio.svelte'),
    'exploit': () => import('$lib/components/ExploitEngine.svelte'),
    'forensics': () => import('$lib/components/ForensicsKit.svelte'),
    
    // Intelligence & Analytics
    'threat-intel': () => import('$lib/components/ThreatIntelligence.svelte'),
    'behavioral-analytics': () => import('$lib/components/BehavioralAnalytics.svelte'),
    'predictive-security': () => import('$lib/components/PredictiveSecurity.svelte'),
    
    // Enterprise Integration & Orchestration
    'orchestration': () => import('$lib/components/OrchestrationDashboard.svelte'),
    'compliance': () => import('$lib/components/ComplianceManager.svelte'),
    'compliance-dashboard': () => import('$lib/components/ComplianceDashboard.svelte'),
    'reporting': () => import('$lib/components/ReportingStudio.svelte'),
    'multi-tenant': () => import('$lib/components/MultiTenantManager.svelte'),
    'integration-hub': () => import('$lib/components/IntegrationHub.svelte'),
    
    // Advanced Security Operations & Automation
    'autonomous-soc': () => import('$lib/components/AutonomousSOC.svelte'),
    'security-automation': () => import('$lib/components/SecurityAutomationPlatform.svelte'),
    'quantum-safe-ops': () => import('$lib/components/QuantumSafeOperations.svelte'),
    'global-threat-intel': () => import('$lib/components/GlobalThreatIntelligence.svelte'),
    
    // Analytics
    'ghostdash': () => import('$lib/components/GhostDash.svelte'),
    'ghostlog': () => import('$lib/components/GhostLog.svelte'),
    'ghostreport': () => import('$lib/components/GhostReport.svelte'),
    'ghostscript': () => import('$lib/components/GhostScript.svelte'),
    
    // System
    'filemanager': () => import('$lib/components/FileManager.svelte'),
    'settings': () => import('$lib/components/Settings.svelte')
  };
  
  // Function to load component dynamically
  async function loadComponent(moduleName: string) {
    if (!loadedComponents[moduleName] && componentMap[moduleName]) {
      try {
        const module = await componentMap[moduleName]();
        loadedComponents[moduleName] = module.default;
      } catch (error) {
        console.error(`Failed to load component for ${moduleName}:`, error);
      }
    }
    return loadedComponents[moduleName];
  }
  
  let activeModule = 'terminal';
  let sidebarCollapsed = false;
  let showThemeManager = false;
  let showFontSettings = false;
  let showNotifications = false;
  let showNavigationSettings = false;
  let notifications: Notification[] = [];
  
  // Font settings state
  let selectedTerminalFont = 'JetBrains Mono';
  let selectedUIFont = 'Inter';
  let fontSize = 14;
  
  // Subscribe to notifications
  const unsubscribeNotifications = notificationsStore.subscribe(value => {
    notifications = value;
  });
  
  // Handle keyboard shortcuts
  onMount(() => {
    const handleKeydown = (e: KeyboardEvent) => {
      // Command Palette (Ctrl/Cmd + K)
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault();
        commandPaletteStore.toggle();
      }
    };
    
    document.addEventListener('keydown', handleKeydown);
    return () => document.removeEventListener('keydown', handleKeydown);
  });
  
  onDestroy(() => {
    unsubscribeNotifications();
  });
  
  function handleModuleSelect(event: CustomEvent<string>) {
    activeModule = event.detail;
  }
  
  function handleCommandExecute(event: CustomEvent<{ command: string; args?: any }>) {
    const { command, args } = event.detail;
    
    switch (command) {
      case 'open_theme_manager':
        showThemeManager = true;
        break;
      case 'open_font_settings':
        showFontSettings = true;
        break;
      case 'toggle_sidebar':
        sidebarCollapsed = !sidebarCollapsed;
        break;
      case 'open_module':
        if (args?.module) {
          activeModule = args.module;
        }
        break;
      default:
        console.log('Unhandled command:', command, args);
    }
  }
  
  function handleShowNotifications() {
    showNotifications = true;
    // Mark all notifications as read when panel is opened
    markAllAsRead();
  }
  
  function handleClearAllNotifications() {
    clearAllNotifications();
    showNotifications = false;
  }

  function handleTerminalFontChange(event: CustomEvent<string>) {
    const fontFamily = event.detail;
    console.log('Terminal font changed:', fontFamily);
    selectedTerminalFont = fontFamily;
  }

  function handleUIFontChange(event: CustomEvent<string>) {
    const fontFamily = event.detail;
    console.log('UI font changed:', fontFamily);
    selectedUIFont = fontFamily;
  }
  
  async function applyFontSettings() {
    try {
      console.log('Applying font settings:', { selectedTerminalFont, selectedUIFont, fontSize });
      
      // Call backend to save and apply settings
      const updatedSettings = await invoke('apply_font_settings', {
        monoFont: selectedTerminalFont,
        uiFont: selectedUIFont,
        fontSize: fontSize
      });
      
      // Update the settings store
      await settingsStore.setFonts({
        monoFont: selectedTerminalFont,
        uiFont: selectedUIFont,
        fontSize: fontSize
      });
      
      console.log('Font settings applied successfully');
      showFontSettings = false;
      
    } catch (error) {
      console.error('Failed to apply font settings:', error);
    }
  }
  
  function getNotificationColor(type: string): string {
    switch (type) {
      case 'success': return 'green';
      case 'warning': return 'yellow';
      case 'error': return 'red';
      default: return 'cyan';
    }
  }
  
  function formatTimestamp(timestamp: Date): string {
    const now = new Date();
    const diff = now.getTime() - timestamp.getTime();
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} minute${minutes > 1 ? 's' : ''} ago`;
    if (hours < 24) return `${hours} hour${hours > 1 ? 's' : ''} ago`;
    return `${days} day${days > 1 ? 's' : ''} ago`;
  }
</script>

<style>
  /* Custom scrollbar for settings */
  .settings-scroll::-webkit-scrollbar {
    width: 8px;
  }
  
  .settings-scroll::-webkit-scrollbar-track {
    background: rgba(255,255,255,0.05);
    border-radius: 4px;
  }
  
  .settings-scroll::-webkit-scrollbar-thumb {
    background: var(--accent-cyan);
    border-radius: 4px;
    opacity: 0.6;
  }
  
  .settings-scroll::-webkit-scrollbar-thumb:hover {
    opacity: 1;
  }
</style>

<div class="flex h-screen w-screen bg-transparent">
  <!-- Sidebar -->
  <Sidebar 
    {activeModule} 
    collapsed={sidebarCollapsed}
    on:module-select={handleModuleSelect}
    on:toggle-collapse={() => sidebarCollapsed = !sidebarCollapsed}
  />
  
  <!-- Main Content Area -->
  <div class="flex-1 flex flex-col">
    <!-- Top Bar -->
    <TopBar 
      {activeModule} 
      on:show-notifications={handleShowNotifications}
      on:module-select={handleModuleSelect}
      on:command-execute={handleCommandExecute}
    />
    
    <!-- Content Area -->
    <div class="flex-1 relative">
      {#if activeModule === 'settings'}
        <!-- Settings Panel -->
        <div class="h-full overflow-y-auto settings-scroll">
          <div class="p-6 space-y-6 min-h-full">
            <div class="frosted rounded-lg p-6">
              <h2 class="text-xl font-bold text-white mb-4" style="font-family: var(--font-display);">Settings</h2>
              
              <div class="space-y-6">
                <!-- Navigation Settings -->
                <div>
                  <h3 class="text-lg font-semibold text-white mb-3">Navigation & Visibility</h3>
                  <div class="space-y-2">
                    <button
                      on:click={() => showNavigationSettings = true}
                      class="w-full text-left px-4 py-3 bg-black/20 border border-gray-700/50 rounded-lg 
                             hover:border-cyan-500/50 transition-colors"
                    >
                      <div class="text-white font-medium">Sidebar Layout</div>
                      <div class="text-gray-400 text-sm">Customize which modules appear in the sidebar and how they're organized</div>
                    </button>
                  </div>
                </div>

                <!-- Theme Settings -->
                <div>
                  <h3 class="text-lg font-semibold text-white mb-3">Appearance</h3>
                  <div class="space-y-2">
                    <button
                      on:click={() => showThemeManager = true}
                      class="w-full text-left px-4 py-3 bg-black/20 border border-gray-700/50 rounded-lg 
                             hover:border-cyan-500/50 transition-colors"
                    >
                      <div class="text-white font-medium">Theme Manager</div>
                      <div class="text-gray-400 text-sm">Advanced theming engine with real-time preview and custom creation</div>
                    </button>
                    
                    <button
                      on:click={() => showFontSettings = true}
                      class="w-full text-left px-4 py-3 bg-black/20 border border-gray-700/50 rounded-lg 
                             hover:border-cyan-500/50 transition-colors"
                    >
                      <div class="text-white font-medium">Font Settings</div>
                      <div class="text-gray-400 text-sm">Choose terminal and UI fonts</div>
                    </button>
                  </div>
                </div>
                
                <!-- Accessibility Settings -->
                <div>
                  <AccessibilitySettings 
                    on:setting-change={(e) => console.log('Accessibility setting changed:', e.detail)}
                  />
                </div>
              </div>
            </div>
          </div>
        </div>
      {:else}
        <!-- Dynamic Components -->
        {#await loadComponent(activeModule)}
          <div class="flex items-center justify-center h-full">
            <div class="text-center">
              <div class="animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-400 mx-auto mb-4"></div>
              <p class="text-gray-400">Loading {activeModule}...</p>
            </div>
          </div>
        {:then Component}
          {#if Component}
            <svelte:component this={Component} on:show-notifications={handleShowNotifications} />
          {:else}
            <!-- Unknown module -->
            <div class="flex items-center justify-center h-full">
              <div class="frosted rounded-lg p-8 text-center">
                <p class="text-gray-400">Module "{activeModule}" not found</p>
              </div>
            </div>
          {/if}
        {:catch error}
          <!-- Error loading component -->
          <div class="flex items-center justify-center h-full">
            <div class="frosted rounded-lg p-8 text-center">
              <p class="text-red-400">Error loading component: {error.message}</p>
              <button 
                on:click={() => location.reload()} 
                class="mt-4 px-4 py-2 bg-red-500/20 border border-red-500/50 rounded-lg hover:bg-red-500/30 transition-colors text-red-400"
              >
                Reload
              </button>
            </div>
          </div>
        {/await}
      {/if}
    </div>
  </div>
</div>

<!-- Overlays -->
<CommandPalette on:execute={handleCommandExecute} />
<NotificationContainer />

<!-- Modals -->
{#if showThemeManager}
  <ThemeManagerV2 bind:isOpen={showThemeManager} />
{/if}

{#if showNavigationSettings}
  <div class="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
    <div class="w-full max-w-6xl h-full max-h-[90vh] bg-black/90 backdrop-blur-sm border border-gray-700/50 rounded-xl overflow-hidden">
      <div class="h-full flex flex-col">
        <div class="flex items-center justify-between p-4 border-b border-gray-700/50">
          <h3 class="text-lg font-semibold text-white">Navigation & Visibility Settings</h3>
          <button
            on:click={() => showNavigationSettings = false}
            class="p-2 rounded-lg hover:bg-white/10 transition-colors text-gray-400 hover:text-white"
          >
            <X size={20} />
          </button>
        </div>
        <div class="flex-1 overflow-hidden">
          <NavigationSettings />
        </div>
      </div>
    </div>
  </div>
{/if}

{#if showFontSettings}
  <div class="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
    <div class="frosted border border-gray-700/50 rounded-xl w-full max-w-md p-6">
      <h3 class="text-lg font-semibold text-white mb-4" style="font-family: var(--font-display);">Font Settings</h3>
      
      <div class="space-y-4">
        <FontSelector 
          label="Terminal Font" 
          fontType="mono"
          selectedFont={selectedTerminalFont}
          on:font-change={handleTerminalFontChange}
        />
        
        <FontSelector 
          label="Interface Font" 
          fontType="ui"
          selectedFont={selectedUIFont}
          on:font-change={handleUIFontChange}
        />
      </div>
      
      <div class="flex space-x-3 mt-6">
        <button
          on:click={applyFontSettings}
          class="flex-1 px-4 py-2 bg-cyan-500/20 border border-cyan-500/50 rounded-lg 
                 hover:bg-cyan-500/30 transition-colors text-cyan-400"
        >
          Apply
        </button>
        <button
          on:click={() => showFontSettings = false}
          class="flex-1 px-4 py-2 bg-gray-500/20 border border-gray-500/50 rounded-lg 
                 hover:bg-gray-500/30 transition-colors text-gray-400"
        >
          Cancel
        </button>
      </div>
    </div>
  </div>
{/if}

{#if showNotifications}
  <div class="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-start justify-end pt-20 pr-4 z-50">
    <div class="frosted border border-gray-700/50 rounded-xl w-full max-w-sm p-4">
      <div class="flex items-center justify-between mb-4">
        <h3 class="text-lg font-semibold text-white" style="font-family: var(--font-display);">Notifications</h3>
        <button
          on:click={() => showNotifications = false}
          class="p-1 rounded hover:bg-white/10 transition-colors text-gray-400 hover:text-white"
        >
          <X size={16} />
        </button>
      </div>
      
      <div class="space-y-3 max-h-96 overflow-y-auto">
        {#if notifications.length === 0}
          <div class="text-center py-8">
            <p class="text-gray-400 text-sm">No notifications</p>
          </div>
        {:else}
          {#each notifications as notification}
            <div class="p-3 bg-{getNotificationColor(notification.type)}-500/10 border border-{getNotificationColor(notification.type)}-500/30 rounded-lg">
              <div class="flex items-start space-x-2">
                <div class="w-2 h-2 bg-{getNotificationColor(notification.type)}-400 rounded-full mt-2 flex-shrink-0"></div>
                <div class="flex-1">
                  <p class="text-sm font-medium text-{getNotificationColor(notification.type)}-400">{notification.title}</p>
                  {#if notification.message}
                    <p class="text-xs text-gray-300 mt-1">{notification.message}</p>
                  {/if}
                  <p class="text-xs text-gray-500 mt-1">{formatTimestamp(notification.timestamp)}</p>
                </div>
              </div>
            </div>
          {/each}
        {/if}
      </div>
      
      <div class="mt-4 pt-3 border-t border-gray-700/50">
        <button
          class="w-full px-3 py-2 text-sm bg-gray-500/20 border border-gray-500/50 rounded-lg 
                 hover:bg-gray-500/30 transition-colors text-gray-400"
          on:click={handleClearAllNotifications}
        >
          Clear All
        </button>
      </div>
    </div>
  </div>
{/if}
