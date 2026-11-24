import { useEffect, useRef, type ReactNode } from 'react';
import { useSecurityText } from './accountSecurity';
export function AccountDialog({title,children,onClose,pending=false}:{title:string;children:ReactNode;onClose:()=>void;pending?:boolean}) {
  const ref=useRef<HTMLDialogElement>(null), t=useSecurityText();
  useEffect(()=>{const d=ref.current!, previous=document.activeElement as HTMLElement|null;if(d.showModal)d.showModal();else d.setAttribute('open','');d.querySelector<HTMLButtonElement>('[data-dismiss]')?.focus();return()=>{if(d.close)d.close();if(previous?.isConnected)previous.focus();};},[]);
  return <dialog ref={ref} className="panel account-dialog" aria-modal="true" aria-labelledby="account-dialog-heading" onCancel={e=>{e.preventDefault();if(!pending)onClose();}} onKeyDown={e=>{
    if(e.key!=='Tab')return;const nodes=ref.current?.querySelectorAll<HTMLElement>('button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled)');if(!nodes?.length)return;
    const first=nodes[0],last=nodes[nodes.length-1];if(e.shiftKey && document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey && document.activeElement===last){e.preventDefault();first.focus();}
  }}><h2 id="account-dialog-heading">{title}</h2><button data-dismiss type="button" className="secondary" disabled={pending} onClick={onClose}>{t('Close','닫기')}</button>{children}</dialog>;
}
export function AccountPagination({offset,total,count,pending,onChange,limit=50}:{offset:number;total?:number;count:number;pending:boolean;onChange:(value:number)=>void;limit?:number}) {
 const t=useSecurityText();return <nav className="account-pagination" aria-label={t('Page navigation','페이지 탐색')}><span>{total===undefined?t('Total unavailable','전체 개수 확인 불가'):`${total===0?0:offset+1}–${offset+count} / ${total}`}</span><button type="button" disabled={pending||offset===0} onClick={()=>onChange(Math.max(0,offset-limit))}>{t('Previous page','이전 페이지')}</button><button type="button" disabled={pending||total===undefined||offset+limit>=total||offset+limit>10000000} onClick={()=>onChange(offset+limit)}>{t('Next page','다음 페이지')}</button></nav>;
}
export function AccountNotice({error,notice}:{error?:string;notice?:string}) {
 const t=useSecurityText();return <>{error && <p role="alert">{t('Request not confirmed. Review the current state before trying again.','요청이 확인되지 않았습니다. 다시 시도하기 전에 현재 상태를 확인하세요.')} <code>{error}</code></p>}{notice && <p role="status">{notice}</p>}</>;
}
