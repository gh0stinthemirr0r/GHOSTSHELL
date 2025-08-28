<script lang="ts">
  import Sidebar from '$lib/components/Sidebar.svelte';
  import TopBar from '$lib/components/TopBar.svelte';
  import Terminal from '$lib/components/Terminal.svelte';
  import CommandPalette from '$lib/components/CommandPalette.svelte';
  import NotificationContainer from '$lib/components/NotificationContainer.svelte';
  import ThemeManagerV2 from '$lib/components/ThemeManagerV2.svelte';
  import FontSelector from '$lib/components/FontSelector.svelte';
  import AccessibilitySettings from '$lib/components/AccessibilitySettings.svelte';
  import GhostVault from '$lib/components/GhostVault.svelte';
  import SecurityPolicy from '$lib/components/SecurityPolicy.svelte';
  // Phase 3 Components
  import SshClient from '$lib/components/SshClient.svelte';
  import VpnClient from '$lib/components/VpnClient.svelte';
  import AiAssistant from '$lib/components/AiAssistant.svelte';
  import FileManager from '$lib/components/FileManager.svelte';
  import NetworkTopology from '$lib/components/NetworkTopology.svelte';
  import LayersTool from '$lib/components/LayersTool.svelte';
  import SurveyorTool from '$lib/components/SurveyorTool.svelte';
  import PcapStudio from '$lib/components/PcapStudio.svelte';
  import ExploitEngine from '$lib/components/ExploitEngine.svelte';
  import ForensicsKit from '$lib/components/ForensicsKit.svelte';
  import ThreatIntelligence from '$lib/components/ThreatIntelligence.svelte';
  import BehavioralAnalytics from '$lib/components/BehavioralAnalytics.svelte';
  import PredictiveSecurity from '$lib/components/PredictiveSecurity.svelte';
  import OrchestrationDashboard from '$lib/components/OrchestrationDashboard.svelte';
  import ComplianceManager from '$lib/components/ComplianceManager.svelte';
  import ReportingStudio from '$lib/components/ReportingStudio.svelte';
  import MultiTenantManager from '$lib/components/MultiTenantManager.svelte';
  import IntegrationHub from '$lib/components/IntegrationHub.svelte';
  import AutonomousSOC from '$lib/components/AutonomousSOC.svelte';
  import AISecurityEngine from '$lib/components/AISecurityEngine.svelte';
  import SecurityAutomationPlatform from '$lib/components/SecurityAutomationPlatform.svelte';
  import QuantumSafeOperations from '$lib/components/QuantumSafeOperations.svelte';
  import GlobalThreatIntelligence from '$lib/components/GlobalThreatIntelligence.svelte';
  import QuantumMLEngine from '$lib/components/QuantumMLEngine.svelte';
  import QuantumCryptography from '$lib/components/QuantumCryptography.svelte';
  import DigitalConsciousness from '$lib/components/DigitalConsciousness.svelte';
  import RealityDefenseMatrix from '$lib/components/RealityDefenseMatrix.svelte';
  import TemporalSecurityEngine from '$lib/components/TemporalSecurityEngine.svelte';
  import UniversalSecurityProtocol from '$lib/components/UniversalSecurityProtocol.svelte';
  import TranscendenceCore from '$lib/components/TranscendenceCore.svelte';
  import ComplianceDashboard from '$lib/components/ComplianceDashboard.svelte';
  import { commandPaletteStore } from '$lib/stores/commandPalette';
  import { onMount } from 'svelte';
  import { Activity } from 'lucide-svelte';
  
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
              {#if activeModule === 'terminal'}
          <Terminal />
        {:else if activeModule === 'ghostssh'}
          <SshClient />
        {:else if activeModule === 'ghostvpn'}
          <VpnClient />
        {:else if activeModule === 'ghostai'}
          <AiAssistant />
        {:else if activeModule === 'topology'}
          <NetworkTopology />
        {:else if activeModule === 'layers'}
          <LayersTool />
        {:else if activeModule === 'surveyor'}
          <SurveyorTool />
        {:else if activeModule === 'filemanager'}
          <FileManager />
        {:else if activeModule === 'pcap'}
          <PcapStudio />
        {:else if activeModule === 'exploit'}
          <ExploitEngine />
        {:else if activeModule === 'forensics'}
          <ForensicsKit />
        {:else if activeModule === 'threat-intel'}
          <ThreatIntelligence />
        {:else if activeModule === 'behavioral-analytics'}
          <BehavioralAnalytics />
          {:else if activeModule === 'predictive-security'}
    <PredictiveSecurity />
          {:else if activeModule === 'orchestration'}
          <OrchestrationDashboard />
        {:else if activeModule === 'compliance'}
          <ComplianceManager />
        {:else if activeModule === 'compliance-dashboard'}
          <ComplianceDashboard />
        {:else if activeModule === 'reporting'}
          <ReportingStudio />
        {:else if activeModule === 'multi-tenant'}
          <MultiTenantManager />
        {:else if activeModule === 'integration-hub'}
          <IntegrationHub />
        {:else if activeModule === 'autonomous-soc'}
          <AutonomousSOC />
        {:else if activeModule === 'ai-security-engine'}
          <AISecurityEngine />
        {:else if activeModule === 'security-automation'}
          <SecurityAutomationPlatform />
        {:else if activeModule === 'quantum-safe-ops'}
          <QuantumSafeOperations />
            {:else if activeModule === 'global-threat-intel'}
      <GlobalThreatIntelligence />
    {:else if activeModule === 'quantum-ml-engine'}
      <QuantumMLEngine />
    {:else if activeModule === 'quantum-cryptography'}
      <QuantumCryptography />
    {:else if activeModule === 'neural-defense-grid'}
      <div class="p-6 text-center">
        <h2 class="text-2xl font-bold text-white mb-4">Neural Defense Grid</h2>
        <p class="text-gray-400">AI-powered autonomous protection swarm coming soon...</p>
      </div>
    {:else if activeModule === 'quantum-forensics'}
      <div class="p-6 text-center">
        <h2 class="text-2xl font-bold text-white mb-4">Quantum Forensics Engine</h2>
        <p class="text-gray-400">Quantum-enhanced investigation tools coming soon...</p>
      </div>
    {:else if activeModule === 'ai-orchestrator'}
      <div class="p-6 text-center">
        <h2 class="text-2xl font-bold text-white mb-4">AI Security Orchestrator</h2>
        <p class="text-gray-400">Autonomous decision making system coming soon...</p>
      </div>
    {:else if activeModule === 'digital-consciousness'}
      <DigitalConsciousness />
    {:else if activeModule === 'reality-defense'}
      <RealityDefenseMatrix />
    {:else if activeModule === 'temporal-security'}
      <TemporalSecurityEngine />
    {:else if activeModule === 'universal-security'}
      <UniversalSecurityProtocol />
    {:else if activeModule === 'transcendence-core'}
      <TranscendenceCore />
  {:else if activeModule === 'ghostvault'}
          <GhostVault />
        {:else if activeModule === 'security'}
          <SecurityPolicy />
      {:else if activeModule === 'settings'}
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
        <!-- Other modules placeholder -->
        <div class="flex items-center justify-center h-full">
          <div class="frosted rounded-lg p-8 text-center">
            <p class="text-gray-400">Module coming in future phases</p>
          </div>
        </div>
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
