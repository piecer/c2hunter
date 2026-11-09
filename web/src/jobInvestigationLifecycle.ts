import { captureAuthentication, currentAuthentication } from './authentication';
import { jobSHA256 } from './jobInvestigationHash';
import { InvestigationOwner } from './investigationLifecycle';
import { assertJobIdentity, decodeJobJSON, JobContractError, parseJobWire } from './jobInvestigationContract';
import type { JobRun } from './jobInvestigationTypes';

type Channel='post'|'history'|'poll'|'evidence'|'cancel'|'capability'|'steps';
/** Per-channel replacement plus whole-session generation fencing. Never POST cancel on retirement. */
export class JobReads {
  private owners=new Map<Channel,InvestigationOwner>();
  request<T>(channel:Channel,task:(signal:AbortSignal)=>Promise<T>,success:(value:T)=>void,failure:(error:unknown)=>void,timeout=15000){
    this.owners.get(channel)?.cancel();const owner=new InvestigationOwner();this.owners.set(channel,owner);
    const authority=captureAuthentication();
    return owner.request(task,value=>{if(currentAuthentication(authority))success(value);},error=>{if(currentAuthentication(authority))failure(error);},timeout);
  }
  retire(){for(const owner of this.owners.values())owner.cancel();this.owners.clear();}
  retireChannel(channel:Channel){this.owners.get(channel)?.cancel();this.owners.delete(channel);}
}
type StoragePort=Pick<Storage,'getItem'|'setItem'|'removeItem'>;
type Pending={job:string;body:string};
const KEY='c2hunter-job-investigation-pending-v1';
/** One bounded, tab-local unresolved admission. No eviction/rebinding/retry on mount.
 * Storage failures block fresh admission; history remains independent.
 */
export class JobIntent {
  private authority=jobSHA256(JSON.stringify(['job-intent-authority-v1',captureAuthentication().token]));
  constructor(private storage:StoragePort){}
  pending():Pending|null{
    if(this.authority!==jobSHA256(JSON.stringify(['job-intent-authority-v1',captureAuthentication().token])))throw new Error('Authentication changed; reopen the investigation');
    const raw=this.storage.getItem(KEY);if(raw===null)return null;
    const value=decodeJobJSON(raw,32768);
    if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).sort().join(',')!=='authority,body,job')throw new JobContractError();
    const p=value as Pending & {authority:string};
    if(p.authority!==this.authority)throw new Error('An unresolved admission belongs to another authentication session; return to that session to recover it');
    if(typeof p.job!=='string'||!/^[!-~]{1,200}$/.test(p.job)||typeof p.body!=='string')throw new JobContractError();
    parseJobWire('request',p.body);return {job:p.job,body:p.body};
  }
  capture(job:string,body:string){
    const pending=this.pending();if(pending&&(pending.job!==job||pending.body!==body))throw new Error('An unresolved admission already exists; recover it before starting another');
    parseJobWire('request',body);this.storage.setItem(KEY,JSON.stringify({authority:this.authority,job,body}));
    const saved=this.pending();if(saved?.job!==job||saved.body!==body)throw new Error('Admission intent storage verification failed');
  }
  resolve(run:JobRun){
    const pending=this.pending();if(!pending)throw new JobContractError();
    assertJobIdentity(run,pending.job,undefined,parseJobWire('request',pending.body));
    this.storage.removeItem(KEY);if(this.pending()!==null)throw new Error('Admission receipt removal unconfirmed');
  }
}
