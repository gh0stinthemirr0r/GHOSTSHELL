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
		client: {"start":"_app/immutable/entry/start.897afa35.js","app":"_app/immutable/entry/app.a67683f6.js","imports":["_app/immutable/entry/start.897afa35.js","_app/immutable/chunks/scheduler.78e7c9ac.js","_app/immutable/chunks/singletons.b41e33e9.js","_app/immutable/chunks/index.8ea75e04.js","_app/immutable/entry/app.a67683f6.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.78e7c9ac.js","_app/immutable/chunks/index.93082cef.js"],"stylesheets":[],"fonts":[]},
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
