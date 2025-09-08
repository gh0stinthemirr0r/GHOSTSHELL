

export const index = 1;
let component_cache;
export const component = async () => component_cache ??= (await import('../entries/fallbacks/error.svelte.js')).default;
export const imports = ["_app/immutable/nodes/1.7ad82273.js","_app/immutable/chunks/scheduler.621791d8.js","_app/immutable/chunks/index.de4558f1.js","_app/immutable/chunks/singletons.a3c4a576.js","_app/immutable/chunks/index.0c640a3e.js"];
export const stylesheets = [];
export const fonts = [];
