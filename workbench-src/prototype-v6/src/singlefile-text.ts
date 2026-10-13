/** Replacement callbacks preserve JavaScript/CSS dollar sequences verbatim. */
export function replaceLiteral(source:string, search:string, replacement:string):string {
 return source.replace(search,()=>replacement)
}
export function escapeHtmlRawText(source:string):string {
 return source.replace(/<\/(script|style)/gi,'<\\/$1')
}
