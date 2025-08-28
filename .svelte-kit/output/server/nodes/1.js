

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.3daf81e4.js","_app/immutable/chunks/scheduler.a8b88eab.js","_app/immutable/chunks/index.8884acef.js","_app/immutable/chunks/singletons.430667a7.js","_app/immutable/chunks/index.680dda78.js"];
export const stylesheets = [];
export const fonts = [];
