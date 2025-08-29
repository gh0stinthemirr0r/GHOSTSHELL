import{c as _,s as w,v as f,m as p}from"./ssr.js";let v="",u=v;const m={base:v,assets:u};function C(){v=m.base,u=m.assets}function F(n){u=m.assets=n}let x={};function P(n){}function S(n){x=n}function O(){}const j=_((n,t,e,g)=>{let{stores:o}=t,{page:d}=t,{constructors:r}=t,{components:s=[]}=t,{form:i}=t,{data_0:c=null}=t,{data_1:h=null}=t;w("__svelte__",o),o.page.notify,t.stores===void 0&&e.stores&&o!==void 0&&e.stores(o),t.page===void 0&&e.page&&d!==void 0&&e.page(d),t.constructors===void 0&&e.constructors&&r!==void 0&&e.constructors(r),t.components===void 0&&e.components&&s!==void 0&&e.components(s),t.form===void 0&&e.form&&i!==void 0&&e.form(i),t.data_0===void 0&&e.data_0&&c!==void 0&&e.data_0(c),t.data_1===void 0&&e.data_1&&h!==void 0&&e.data_1(h);let l,y,k=n.head;do l=!0,n.head=k,o.page.set(d),y=`  ${r[1]?`${f(r[0]||p,"svelte:component").$$render(n,{data:c,this:s[0]},{this:a=>{s[0]=a,l=!1}},{default:()=>`${f(r[1]||p,"svelte:component").$$render(n,{data:h,form:i,this:s[1]},{this:a=>{s[1]=a,l=!1}},{})}`})}`:`${f(r[0]||p,"svelte:component").$$render(n,{data:c,form:i,this:s[0]},{this:a=>{s[0]=a,l=!1}},{})}`} `;while(!l);return y}),U={app_template_contains_nonce:!1,csp:{mode:"auto",directives:{"upgrade-insecure-requests":!1,"block-all-mixed-content":!1},reportOnly:{"upgrade-insecure-requests":!1,"block-all-mixed-content":!1}},csrf_check_origin:!0,track_server_fetches:!1,embedded:!1,env_public_prefix:"PUBLIC_",env_private_prefix:"",hooks:null,preload_strategy:"modulepreload",root:j,service_worker:!1,templates:{app:({head:n,body:t,assets:e,nonce:g,env:o})=>`<!DOCTYPE html>\r
<html lang="en" class="dark">\r
  <head>\r
    <meta charset="utf-8" />\r
    <link rel="icon" href="`+e+`/favicon.png" />\r
    <meta name="viewport" content="width=device-width, initial-scale=1" />\r
    <title>GHOSTSHELL - Professional Post-Quantum Terminal</title>\r
    <!-- Futuristic Fonts -->\r
    <link rel="preconnect" href="https://fonts.googleapis.com">\r
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>\r
    <!-- Comprehensive Nerd Fonts Collection -->\r
    <!-- Google Fonts -->\r
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300;400;500;600;700&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Source+Code+Pro:ital,wght@0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Ubuntu+Mono:ital,wght@0,400;0,700;1,400;1,700&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Inconsolata:wght@200;300;400;500;600;700;800;900&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Roboto+Mono:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;1,100;1,200;1,300;1,400;1,500;1,600;1,700&display=swap" rel="stylesheet">\r
    \r
    <!-- Nerd Fonts via jsDelivr CDN -->\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/cascadia-code@4.2.1/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/hack@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/iosevka@4.5.0/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/victor-mono@4.0.1/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/anonymous-pro@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/cousine@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/dejavu-sans-mono@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/droid-sans-mono@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/liberation-mono@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/noto-sans-mono@4.5.0/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/overpass-mono@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/space-mono@4.0.2/index.css" rel="stylesheet">\r
    <link href="https://cdn.jsdelivr.net/npm/@fontsource/ubuntu-mono@4.0.2/index.css" rel="stylesheet">\r
    \r
    <!-- Additional Professional Fonts -->\r
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@100;200;300;400;500;600;700;800;900&display=swap" rel="stylesheet">\r
    <link href="https://fonts.googleapis.com/css2?family=Poppins:ital,wght@0,100;0,200;0,300;0,400;0,500;0,600;0,700;0,800;0,900;1,100;1,200;1,300;1,400;1,500;1,600;1,700;1,800;1,900&display=swap" rel="stylesheet">\r
    `+n+`\r
  </head>\r
  <body data-sveltekit-preload-data="hover" class="bg-transparent overflow-hidden">\r
    <div style="display: contents">`+t+`</div>\r
  </body>\r
</html>\r
`,error:({status:n,message:t})=>`<!doctype html>
<html lang="en">
	<head>
		<meta charset="utf-8" />
		<title>`+t+`</title>

		<style>
			body {
				--bg: white;
				--fg: #222;
				--divider: #ccc;
				background: var(--bg);
				color: var(--fg);
				font-family:
					system-ui,
					-apple-system,
					BlinkMacSystemFont,
					'Segoe UI',
					Roboto,
					Oxygen,
					Ubuntu,
					Cantarell,
					'Open Sans',
					'Helvetica Neue',
					sans-serif;
				display: flex;
				align-items: center;
				justify-content: center;
				height: 100vh;
				margin: 0;
			}

			.error {
				display: flex;
				align-items: center;
				max-width: 32rem;
				margin: 0 1rem;
			}

			.status {
				font-weight: 200;
				font-size: 3rem;
				line-height: 1;
				position: relative;
				top: -0.05rem;
			}

			.message {
				border-left: 1px solid var(--divider);
				padding: 0 0 0 1rem;
				margin: 0 0 0 1rem;
				min-height: 2.5rem;
				display: flex;
				align-items: center;
			}

			.message h1 {
				font-weight: 400;
				font-size: 1em;
				margin: 0;
			}

			@media (prefers-color-scheme: dark) {
				body {
					--bg: #222;
					--fg: #ddd;
					--divider: #666;
				}
			}
		</style>
	</head>
	<body>
		<div class="error">
			<span class="status">`+n+`</span>
			<div class="message">
				<h1>`+t+`</h1>
			</div>
		</div>
	</body>
</html>
`},version_hash:"1k90kmw"};function I(){return{}}export{u as a,v as b,S as c,F as d,O as e,I as g,U as o,x as p,C as r,P as s};
