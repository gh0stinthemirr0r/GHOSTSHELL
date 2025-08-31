

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.7fbf1c49.js","_app/immutable/chunks/scheduler.621791d8.js","_app/immutable/chunks/index.de4558f1.js","_app/immutable/chunks/singletons.0549b2ec.js","_app/immutable/chunks/index.0c640a3e.js"];
export const stylesheets = [];
export const fonts = [];
