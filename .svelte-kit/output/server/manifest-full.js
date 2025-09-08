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
		client: {"start":"_app/immutable/entry/start.50593207.js","app":"_app/immutable/entry/app.f39e28f0.js","imports":["_app/immutable/entry/start.50593207.js","_app/immutable/chunks/scheduler.621791d8.js","_app/immutable/chunks/singletons.a3c4a576.js","_app/immutable/chunks/index.0c640a3e.js","_app/immutable/entry/app.f39e28f0.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.621791d8.js","_app/immutable/chunks/index.de4558f1.js"],"stylesheets":[],"fonts":[]},
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
