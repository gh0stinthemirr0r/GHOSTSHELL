

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.70f54d4f.js","_app/immutable/chunks/scheduler.2cab2851.js","_app/immutable/chunks/index.23964f24.js","_app/immutable/chunks/singletons.8b161670.js","_app/immutable/chunks/index.a5826648.js"];
export const stylesheets = [];
export const fonts = [];
