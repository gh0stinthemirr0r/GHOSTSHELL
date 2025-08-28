<script lang="ts">
  // Only import essential components that are always needed
  import Sidebar from '$lib/components/Sidebar.svelte';
  import TopBar from '$lib/components/TopBar.svelte';
  import CommandPalette from '$lib/components/CommandPalette.svelte';
  import NotificationContainer from '$lib/components/NotificationContainer.svelte';
  import ThemeManagerV2 from '$lib/components/ThemeManagerV2.svelte';
  import FontSelector from '$lib/components/FontSelector.svelte';
  import AccessibilitySettings from '$lib/components/AccessibilitySettings.svelte';
  import { commandPaletteStore } from '$lib/stores/commandPalette';
  import { onMount } from 'svelte';
  import { Activity } from 'lucide-svelte';
  
  // Lazy loading for heavy components
  let loadedComponents: Record<string, any> = {};
  
  // Component loading map
  const componentMap: Record<string, () => Promise<any>> = {
    'terminal': () => import('$lib/components/Terminal.svelte'),
    'ghostssh': () => import('$lib/components/SshClient.svelte'),
    'ghostvpn': () => import('$lib/components/VpnClient.svelte'),
    'ghostai': () => import('$lib/components/AiAssistant.svelte'),
    'topology': () => import('$lib/components/NetworkTopology.svelte'),
    'layers': () => import('$lib/components/LayersTool.svelte'),
    'surveyor': () => import('$lib/components/SurveyorTool.svelte'),
    'filemanager': () => import('$lib/components/FileManager.svelte'),
    'pcap': () => import('$lib/components/PcapStudio.svelte'),
    'exploit': () => import('$lib/components/ExploitEngine.svelte'),
    'forensics': () => import('$lib/components/ForensicsKit.svelte'),
    'threat-intel': () => import('$lib/components/ThreatIntelligence.svelte'),
    'behavioral-analytics': () => import('$lib/components/BehavioralAnalytics.svelte'),
    'predictive-security': () => import('$lib/components/PredictiveSecurity.svelte'),
    'orchestration': () => import('$lib/components/OrchestrationDashboard.svelte'),
    'compliance': () => import('$lib/components/ComplianceManager.svelte'),
    'compliance-dashboard': () => import('$lib/components/ComplianceDashboard.svelte'),
    'reporting': () => import('$lib/components/ReportingStudio.svelte'),
    'multi-tenant': () => import('$lib/components/MultiTenantManager.svelte'),
    'integration-hub': () => import('$lib/components/IntegrationHub.svelte'),
    'autonomous-soc': () => import('$lib/components/AutonomousSOC.svelte'),
    'security-automation': () => import('$lib/components/SecurityAutomationPlatform.svelte'),
    'quantum-safe-ops': () => import('$lib/components/QuantumSafeOperations.svelte'),
    'global-threat-intel': () => import('$lib/components/GlobalThreatIntelligence.svelte'),
    'ghostvault': () => import('$lib/components/GhostVault.svelte'),
    'security': () => import('$lib/components/SecurityPolicy.svelte')
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

  function handleTerminalFontChange(event: CustomEvent<string>) {
    const fontFamily = event.detail;
    console.log('Terminal font changed:', fontFamily);
    
    // Apply to CSS variables
    document.documentElement.style.setProperty('--font-mono', `"${fontFamily}", ui-monospace, SFMono-Regular, monospace`);
    
    // TODO: Apply to terminal instance if available
  }

  function handleUIFontChange(event: CustomEvent<string>) {
    const fontFamily = event.detail;
    console.log('UI font changed:', fontFamily);
    
    // Apply to CSS variables
    document.documentElement.style.setProperty('--font-ui', `"${fontFamily}", ui-sans-serif, system-ui, sans-serif`);
    document.documentElement.style.setProperty('--font-display', `"${fontFamily}", ui-sans-serif, system-ui, sans-serif`);
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
    <TopBar {activeModule} />
    
    <!-- Content Area -->
    <div class="flex-1 relative">
      {#if activeModule === 'settings'}
        <!-- Settings Panel -->
        <div class="h-full overflow-y-auto settings-scroll">
          <div class="p-6 space-y-6 min-h-full">
            <div class="frosted rounded-lg p-6">
              <h2 class="text-xl font-bold text-white mb-4" style="font-family: var(--font-display);">Settings</h2>
              
              <div class="space-y-6">
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
            <svelte:component this={Component} />
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

{#if showFontSettings}
  <div class="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
    <div class="frosted border border-gray-700/50 rounded-xl w-full max-w-md p-6">
      <h3 class="text-lg font-semibold text-white mb-4" style="font-family: var(--font-display);">Font Settings</h3>
      
      <div class="space-y-4">
        <FontSelector 
          label="Terminal Font" 
          fontType="mono"
          selectedFont="JetBrains Mono"
          on:font-change={handleTerminalFontChange}
        />
        
        <FontSelector 
          label="Interface Font" 
          fontType="ui"
          selectedFont="Space Grotesk"
          on:font-change={handleUIFontChange}
        />
      </div>
      
      <div class="flex space-x-3 mt-6">
        <button
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
