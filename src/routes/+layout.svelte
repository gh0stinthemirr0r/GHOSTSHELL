<script lang="ts">
  import '../app.css';
  import { onMount } from 'svelte';
  import { themeStore } from '$lib/stores/theme';
  import { settingsStore } from '$lib/stores/settings';
  import { invoke } from '@tauri-apps/api/tauri';
  
  // Load initial theme and settings
  onMount(async () => {
    try {
      // Load themes
      const themes = await invoke('list_themes');
      themeStore.setThemes(themes);
      
      // Load settings
      const settings = await invoke('get_settings');
      settingsStore.set(settings);
      
      // Apply default theme
      const defaultTheme = themes.find(t => t.id === 'cyberpunk-neon');
      if (defaultTheme) {
        const themeData = await invoke('apply_theme', { themeId: 'cyberpunk-neon' });
        themeStore.setCurrentTheme(themeData);
      }
    } catch (error) {
      console.error('Failed to load initial data:', error);
    }
  });
</script>

<main class="h-screen w-screen bg-transparent">
  <slot />
</main>
