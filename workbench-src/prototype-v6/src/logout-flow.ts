/** Presentation is independent of server authority: a finished animation is never logout proof. */
export type LogoutResult='none'|'pending'|'confirmed'|'failed'|'offline'
export const LOGOUT_DURATION=960
export class LogoutFlow {
 generation=0; progress=0; result:LogoutResult='none'; started=0; active=false
 begin(now:number,offline:boolean,reduced:boolean){if(this.active||this.result==='pending')return null;this.generation++;this.started=now;this.progress=reduced?1:0;this.result=offline?'offline':'pending';this.active=!reduced;return this.generation}
 settle(generation:number,confirmed:boolean){if(generation!==this.generation||this.result!=='pending')return false;this.result=confirmed?'confirmed':'failed';return true}
 update(now:number,reduced=false){if(this.active){this.progress=reduced?1:Math.min(1,Math.max(0,(now-this.started)/LOGOUT_DURATION));if(this.progress===1)this.active=false}return this.progress}
 clear(){if(this.active||this.result==='pending')return false;this.generation++;this.result='none';this.progress=0;return true}
 get blocked(){return this.active||this.result==='pending'}
 get message(){return this.result==='pending'?'本页已锁定，正在等待后端确认退出':this.result==='confirmed'?'所有者会话已退出，请重新核验':this.result==='failed'?'本页已锁定，但后端退出未确认。请重试退出。':this.result==='offline'?'已返回入口。离线预览没有真实登录会话。':''}
}
export function logoutVisuals(progress:number){const p=Math.min(1,Math.max(0,progress)),smooth=(x:number)=>{const v=Math.min(1,Math.max(0,x));return v*v*(3-2*v)};return {detail:1-smooth(p/.38),detailX:-52*smooth(p/.42),workspace:1-smooth((p-.18)/.54),arc:1-smooth((p-.94)/.06),withdraw:smooth((p-.16)/.84)}}
