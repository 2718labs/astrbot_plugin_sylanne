// Package only this frontend. Never writes the backend resource tree or manifest.
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { replaceLiteral,escapeHtmlRawText } from '../src/singlefile-text.ts'
const sha=bytes=>crypto.createHash('sha256').update(bytes).digest('hex')
const htmlPath='dist/index.html',sourceHtml=fs.readFileSync(htmlPath,'utf8')
const scriptMatch=sourceHtml.match(/<script\b[^>]*src="([^"]+)"[^>]*><\/script>/)
const styleMatch=sourceHtml.match(/<link\b[^>]*href="([^"]+\.css)"[^>]*>/)
assert.ok(scriptMatch&&styleMatch,'Expected exactly one Vite JS and CSS bundle')
assert.equal((sourceHtml.match(/<script\b[^>]*src=/g)||[]).length,1,'Unexpected code splitting; single-file packer must be reviewed')
const jsPath=path.join('dist',scriptMatch[1]),cssPath=path.join('dist',styleMatch[1])
const sourceJs=fs.readFileSync(jsPath,'utf8'),css=fs.readFileSync(cssPath,'utf8'),model=fs.readFileSync('dist/models/sylanne-archive-v18.glb')
const fetchModel=/fetch\(([`"])(?:\.\/)?models\/sylanne-archive-v18\.glb\1,\{signal:[\w$]+\.signal\}\)/g
assert.equal([...sourceJs.matchAll(fetchModel)].length,1,'Model loading expression changed; refusing to ship an external-resource package')
const embeddedModelLoader='Promise.resolve({ok:true,status:200,arrayBuffer:async()=>{const text=document.getElementById("sylanne-embedded-model").textContent.trim();const raw=atob(text);return Uint8Array.from(raw,c=>c.charCodeAt(0)).buffer}})'
const js=sourceJs.replace(fetchModel,embeddedModelLoader)
assert.ok(!js.includes('./models/sylanne-archive-v18.glb'))
const escapeClose=escapeHtmlRawText
let html=replaceLiteral(replaceLiteral(sourceHtml,scriptMatch[0],'<script type="module">'+escapeClose(js)+'</script>'),styleMatch[0],'<style>'+escapeClose(css)+'</style>')
html=replaceLiteral(html,'</head>','<script type="application/octet-stream" id="sylanne-embedded-model">'+model.toString('base64')+'</script>\n</head>')
assert.ok(!/<script\b[^>]*src=|<link\b[^>]*href=/.test(html),'External JS/CSS resource remains')
// Validate the exact packaged bytes, not just Vite's pre-packaging bundle.
const packagedJs=html.match(/<script type="module">([\s\S]*?)<\/script>/)?.[1]
assert.equal(packagedJs,escapeClose(js),'Packaging altered JavaScript bytes')
assert.equal(html.match(/<style>([\s\S]*?)<\/style>/)?.[1],escapeClose(css),'Packaging altered CSS bytes')
const syntax=spawnSync(process.execPath,['--input-type=module','--check'],{input:packagedJs,encoding:'utf8'})
assert.equal(syntax.status,0,'Packaged JavaScript syntax invalid: '+syntax.stderr)
const bootstrapScripts=[...html.matchAll(/<script(?![^>]*type=)[^>]*>([\s\S]*?)<\/script>/g)].map(match=>match[1]);
for(const bootstrap of bootstrapScripts){const check=spawnSync(process.execPath,['--check'],{input:bootstrap,encoding:'utf8'});assert.equal(check.status,0,'Theme bootstrap syntax invalid: '+check.stderr)}
const decode=Buffer.from(html.match(/id="sylanne-embedded-model">([^<]+)<\/script>/)[1],'base64')
assert.deepEqual(decode,model,'Embedded actual GLB differs')
const glbJsonLength=model.readUInt32LE(12),glbJson=JSON.parse(model.subarray(20,20+glbJsonLength).toString())
assert.ok(!glbJson.images?.some(i=>i.uri||i.bufferView===undefined)&&!glbJson.buffers?.some(b=>b.uri),'Model requires an external texture/buffer')
fs.mkdirSync('singlefile',{recursive:true})
fs.writeFileSync('singlefile/index.html',html)
const logoSource=fs.readFileSync('src/assets/2718labs-logo.ts','utf8');const logoBase64=logoSource.match(/data:image\/png;base64,([^\"]+)/)[1];const logo=Buffer.from(logoBase64,'base64');assert.ok(html.includes(logoBase64),'Official logo must be embedded byte-for-byte');assert.deepEqual(logo,fs.readFileSync('../official-assets/2718labs-github-avatar.png'));
const receipt={bootstrapScriptSyntaxVerified:true,inlineBootstrapCspHashes:bootstrapScripts.map(code=>'sha256-'+crypto.createHash('sha256').update(code).digest('base64')),embeddedOfficialLogoByteIdentical:true,officialLogoSha256:sha(logo),externalLogoRequests:0,kind:'frontend-only-singlefile-package',buildMode:process.env.VITE_SYLANNE_BACKEND==='same-origin'?'same-origin-api-enabled':'offline-zero-backend-request-default',document:'index.html',bytes:Buffer.byteLength(html),sha256:sha(html),sourceJsSha256:sha(sourceJs),sourceCssSha256:sha(css),glbSha256:sha(model),embeddedGlbByteIdentical:true,externalModelTextureBufferResources:0,externalJsCssModelRequests:0,backendResourcesOrManifestWritten:false,browserOrCspRuntimeVerified:false,packagedJavaScriptSyntaxVerified:true,packagedJsCssByteIdentical:true,inlineScriptCspHash:'sha256-'+crypto.createHash('sha256').update(packagedJs).digest('base64'),inlineStyleCspHash:'sha256-'+crypto.createHash('sha256').update(escapeClose(css)).digest('base64')}
fs.writeFileSync('singlefile/package-receipt.json',JSON.stringify(receipt,null,2))
console.log(JSON.stringify(receipt,null,2))
