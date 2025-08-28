

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.d1304138.js","_app/immutable/chunks/scheduler.78e7c9ac.js","_app/immutable/chunks/index.93082cef.js","_app/immutable/chunks/singletons.b41e33e9.js","_app/immutable/chunks/index.8ea75e04.js"];
export const stylesheets = [];
export const fonts = [];
