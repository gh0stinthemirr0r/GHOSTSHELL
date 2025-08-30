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
		client: {"start":"_app/immutable/entry/start.3f070b76.js","app":"_app/immutable/entry/app.33a3cf99.js","imports":["_app/immutable/entry/start.3f070b76.js","_app/immutable/chunks/scheduler.b5668ba5.js","_app/immutable/chunks/singletons.0bb8e952.js","_app/immutable/chunks/index.0fca93e4.js","_app/immutable/entry/app.33a3cf99.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.b5668ba5.js","_app/immutable/chunks/index.ca943cf7.js"],"stylesheets":[],"fonts":[]},
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
