/** Original interface micro-compositions; provisional, not copied or matched to PV audio. */
export type Cue='dock'|'open'|'back'|'verify'|'success'|'error'
export type Tone={offset:number;from:number;to:number;duration:number;gain:number;wave:OscillatorType}
export const CUE_SPECS:Record<Cue,readonly Tone[]>={
 dock:[{offset:0,from:1160,to:860,duration:.055,gain:.28,wave:'sine'}],
 open:[{offset:0,from:420,to:630,duration:.16,gain:.42,wave:'sine'},{offset:.045,from:1260,to:1260,duration:.12,gain:.10,wave:'sine'}],
 back:[{offset:0,from:530,to:350,duration:.14,gain:.35,wave:'sine'}],
 verify:[{offset:0,from:320,to:480,duration:.19,gain:.35,wave:'sine'}],
 success:[{offset:0,from:480,to:480,duration:.27,gain:.30,wave:'sine'},{offset:.09,from:720,to:720,duration:.29,gain:.24,wave:'sine'}],
 error:[{offset:0,from:280,to:245,duration:.20,gain:.32,wave:'sine'}]
}
export class SoftAudio {
 private context:AudioContext|null=null;private master:GainNode|null=null;private last=-Infinity;private ended=false;private active=new Set<OscillatorNode>();muted=false;volume=.35
 constructor(){try{const pref=JSON.parse(globalThis.localStorage?.getItem('sylanne.audio.v1')??'null');if(pref&&typeof pref.muted==='boolean')this.muted=pref.muted;if(pref&&typeof pref.volume==='number'&&Number.isFinite(pref.volume))this.volume=Math.max(0,Math.min(1,pref.volume))}catch{/* Storage is optional. */}}
 private save(){try{globalThis.localStorage?.setItem('sylanne.audio.v1',JSON.stringify({muted:this.muted,volume:this.volume}))}catch{/* Private browsing and file previews may deny storage. */}}
 async unlock(){if(this.muted||this.ended)return;try{if(!this.context){this.context=new AudioContext();this.master=this.context.createGain();this.master.gain.value=this.volume*.08;this.master.connect(this.context.destination)}if(this.context.state==='suspended')await this.context.resume()}catch{/* Silent fallback: visual and text cues remain sufficient. */}}
 private apply(){if(this.master&&this.context)this.master.gain.setValueAtTime(this.muted?0:this.volume*.08,this.context.currentTime)}
 setMuted(value:boolean){this.muted=value;if(value)this.silence();this.apply();this.save()}
 setVolume(value:number){if(!Number.isFinite(value))return;this.volume=Math.max(0,Math.min(1,value));if(this.volume===0)this.silence();this.apply();this.save()}
 silence(){for(const node of this.active){try{node.stop()}catch{}node.disconnect()}this.active.clear()}
 cue(kind:Cue){const c=this.context;if(this.ended||this.muted||this.volume===0||!c||c.state!=='running'||!this.master)return;const now=c.currentTime;if(now-this.last<.12)return;this.last=now;this.silence();for(const tone of CUE_SPECS[kind]){const oscillator=c.createOscillator(),envelope=c.createGain(),start=now+tone.offset,end=start+tone.duration;oscillator.type=tone.wave;oscillator.frequency.setValueAtTime(tone.from,start);oscillator.frequency.exponentialRampToValueAtTime(tone.to,end);envelope.gain.setValueAtTime(0,start);envelope.gain.linearRampToValueAtTime(tone.gain,start+.008);envelope.gain.exponentialRampToValueAtTime(.0001,end);oscillator.connect(envelope);envelope.connect(this.master);this.active.add(oscillator);oscillator.onended=()=>{this.active.delete(oscillator);oscillator.disconnect();envelope.disconnect()};oscillator.start(start);oscillator.stop(end+.01)}}
 dispose(){this.ended=true;this.silence();void this.context?.close().catch(()=>{});this.context=null;this.master=null}
}
