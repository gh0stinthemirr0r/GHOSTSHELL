

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.88c1c2b3.js","_app/immutable/chunks/scheduler.b5668ba5.js","_app/immutable/chunks/index.ca943cf7.js","_app/immutable/chunks/singletons.0bb8e952.js","_app/immutable/chunks/index.0fca93e4.js"];
export const stylesheets = [];
export const fonts = [];
