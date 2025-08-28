

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.f991aded.js","_app/immutable/chunks/scheduler.4c62dcfe.js","_app/immutable/chunks/index.da97ccc5.js","_app/immutable/chunks/singletons.1f4152e0.js","_app/immutable/chunks/index.57752d85.js"];
export const stylesheets = [];
export const fonts = [];
