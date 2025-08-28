export const manifest = (() => {
function __memo(fn) {
	let value;
	return () => value ??= (value = fn());
}

return {
	appDir: "_app",
	appPath: "_app",
	assets: new Set(["favicon.png"]),
	mimeTypes: {".png":"image/png"},
	_: {
		client: {"start":"_app/immutable/entry/start.d3ee9da9.js","app":"_app/immutable/entry/app.24a070c0.js","imports":["_app/immutable/entry/start.d3ee9da9.js","_app/immutable/chunks/scheduler.4c62dcfe.js","_app/immutable/chunks/singletons.1f4152e0.js","_app/immutable/chunks/index.57752d85.js","_app/immutable/entry/app.24a070c0.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.4c62dcfe.js","_app/immutable/chunks/index.da97ccc5.js"],"stylesheets":[],"fonts":[]},
		nodes: [
			__memo(() => import('./nodes/0.js')),
			__memo(() => import('./nodes/1.js')),
			__memo(() => import('./nodes/2.js'))
		],
		routes: [
			{
				id: "/",
				pattern: /^\/$/,
				params: [],
				page: { layouts: [0,], errors: [1,], leaf: 2 },
				endpoint: null
			}
		],
		matchers: async () => {
			
			return {  };
		}
	}
}
})();
