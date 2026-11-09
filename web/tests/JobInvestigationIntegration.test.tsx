import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { expect, it, vi } from 'vitest';
import App from '../src/App';
import { api } from '../src/api';
it('actual C2 job page exposes a quiet experimental sibling without default promotion',async()=>{
  localStorage.setItem('c2hunter-token','test');
  vi.spyOn(api,'get').mockImplementation(async path=>path==='/analysis-jobs/job'?{id:'job',name:'Job',status:'COMPLETED',analysis:{module:'c2'}}:path==='/ai-capabilities'?{available:false}:{items:[]});
  const post=vi.spyOn(api,'post'),fetch=vi.fn();vi.stubGlobal('fetch',fetch);
  const client=new QueryClient({defaultOptions:{queries:{retry:false}}});
  const view=render(<QueryClientProvider client={client}><MemoryRouter initialEntries={['/analyses/job']}><App/></MemoryRouter></QueryClientProvider>);
  await screen.findByRole('button',{name:/Open IP investigation/});
  expect(screen.getByRole('button',{name:/Open experimental investigation/})).toBeInTheDocument();
  expect(post).not.toHaveBeenCalled();expect(fetch).not.toHaveBeenCalled();view.unmount();client.clear();
});
