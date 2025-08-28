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
		client: {"start":"_app/immutable/entry/start.225ce2af.js","app":"_app/immutable/entry/app.de277d34.js","imports":["_app/immutable/entry/start.225ce2af.js","_app/immutable/chunks/scheduler.2cab2851.js","_app/immutable/chunks/singletons.8b161670.js","_app/immutable/chunks/index.a5826648.js","_app/immutable/entry/app.de277d34.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.2cab2851.js","_app/immutable/chunks/index.23964f24.js"],"stylesheets":[],"fonts":[]},
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
