

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.8ae2ba55.js","_app/immutable/chunks/scheduler.239bea07.js","_app/immutable/chunks/index.83fc6ed7.js","_app/immutable/chunks/singletons.96335ca2.js","_app/immutable/chunks/index.445d6633.js"];
export const stylesheets = [];
export const fonts = [];
