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
		client: {"start":"_app/immutable/entry/start.ddcb615d.js","app":"_app/immutable/entry/app.fc929e6a.js","imports":["_app/immutable/entry/start.ddcb615d.js","_app/immutable/chunks/scheduler.b5668ba5.js","_app/immutable/chunks/singletons.8687fdb2.js","_app/immutable/chunks/index.0fca93e4.js","_app/immutable/entry/app.fc929e6a.js","_app/immutable/chunks/preload-helper.a4192956.js","_app/immutable/chunks/scheduler.b5668ba5.js","_app/immutable/chunks/index.ca943cf7.js"],"stylesheets":[],"fonts":[]},
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
