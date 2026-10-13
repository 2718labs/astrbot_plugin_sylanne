import {test} from 'node:test'
import assert from 'node:assert/strict'
import {spawnSync} from 'node:child_process'
import {replaceLiteral,escapeHtmlRawText} from './singlefile-text.ts'
test('single-file JS and CSS insertion preserves every replacement dollar sequence',()=>{
 const sequences=['$`','$&',"$'",'$$','$1'];
 for(const kind of ['script','style'])for(const token of sequences){
  const payload=kind==='script'?`const token=${JSON.stringify(token)};`:`.token::after{content:${JSON.stringify(token)}}`
  assert.equal(replaceLiteral('PREFIX PLACEHOLDER SUFFIX','PLACEHOLDER',payload),'PREFIX '+payload+' SUFFIX')
 }
})
test('Vue dollar-backtick literal survives packaging and parses as an actual module',()=>{
 const js='const key=`$`; const attrs=`$attrs`;'
 const broken='PREFIX PLACEHOLDER SUFFIX'.replace('PLACEHOLDER',js)
 assert.notEqual(broken,'PREFIX '+js+' SUFFIX')
 const html=replaceLiteral('<script>PLACEHOLDER</script>','PLACEHOLDER',escapeHtmlRawText(js))
 const extracted=html.match(/<script>([\s\S]*?)<\/script>/)![1]!
 assert.equal(extracted,js)
 const result=spawnSync(process.execPath,['--input-type=module','--check'],{input:extracted,encoding:'utf8'})
 assert.equal(result.status,0,result.stderr)
})
test('raw-text closing tags cannot truncate embedded JS or CSS',()=>{
 const js='const tags=["</script>","</ScRiPt >","</style>"];'
 const escaped=escapeHtmlRawText(js)
 assert.doesNotMatch(escaped,/<\/(script|style)/i)
 assert.equal(escaped.replace(/<\\\//g,'</'),js)
 const result=spawnSync(process.execPath,['--input-type=module','--check'],{input:escaped,encoding:'utf8'})
 assert.equal(result.status,0,result.stderr)
})
