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
		client: {"start":"_app/immutable/entry/start.e0cc0c3c.js","app":"_app/immutable/entry/app.cd672ecc.js","imports":["_app/immutable/entry/start.e0cc0c3c.js","_app/immutable/chunks/scheduler.621791d8.js","_app/immutable/chunks/singletons.0549b2ec.js","_app/immutable/chunks/index.0c640a3e.js","_app/immutable/entry/app.cd672ecc.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.621791d8.js","_app/immutable/chunks/index.de4558f1.js"],"stylesheets":[],"fonts":[]},
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
