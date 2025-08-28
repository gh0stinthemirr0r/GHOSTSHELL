

export const index = 2;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/pages/_page.svelte.js')).default;
export const imports = ["_app/immutable/nodes/2.e27cdfdd.js","_app/immutable/chunks/2.77d64b31.js","_app/immutable/chunks/scheduler.2cab2851.js","_app/immutable/chunks/index.23964f24.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/settings.138d31ef.js","_app/immutable/chunks/index.a5826648.js"];
export const stylesheets = ["_app/immutable/assets/2.9c336935.css"];
export const fonts = [];
