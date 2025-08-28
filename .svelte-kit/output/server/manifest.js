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
		client: {"start":"_app/immutable/entry/start.8bec7c62.js","app":"_app/immutable/entry/app.403b5585.js","imports":["_app/immutable/entry/start.8bec7c62.js","_app/immutable/chunks/scheduler.a8b88eab.js","_app/immutable/chunks/singletons.430667a7.js","_app/immutable/chunks/index.680dda78.js","_app/immutable/entry/app.403b5585.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.a8b88eab.js","_app/immutable/chunks/index.8884acef.js"],"stylesheets":[],"fonts":[]},
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
