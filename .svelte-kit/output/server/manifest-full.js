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
		client: {"start":"_app/immutable/entry/start.7975f24c.js","app":"_app/immutable/entry/app.862749c1.js","imports":["_app/immutable/entry/start.7975f24c.js","_app/immutable/chunks/scheduler.239bea07.js","_app/immutable/chunks/singletons.96335ca2.js","_app/immutable/chunks/index.445d6633.js","_app/immutable/entry/app.862749c1.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.239bea07.js","_app/immutable/chunks/index.83fc6ed7.js"],"stylesheets":[],"fonts":[]},
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
