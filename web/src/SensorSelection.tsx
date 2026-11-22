import { useLayoutEffect, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { api } from './api';
import { SensorPagination, type SensorPage } from './SensorPagination';
import { sensorPagePath } from './sensorPagePath';

type Choice = { sensor_id: string; name: string };
export default function SensorSelection({ onSelectionChange }: { onSelectionChange: () => void }) {
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<string[]>([]);
  const [open, setOpen] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const invoker = useRef<HTMLButtonElement>(null);
  const query = useQuery<SensorPage<Choice>, Error>({ queryKey: ['sensors', 'selection', page], queryFn: () => api.get(sensorPagePath('/sensors', page)) });
  const choices = Array.isArray(query.data) ? query.data : query.data?.items ?? [];
  const small = (Array.isArray(query.data) ? choices.length : query.data?.total ?? choices.length) <= 8;
  const close = () => { dialog.current?.close?.(); setOpen(false); invoker.current?.focus(); };
  useLayoutEffect(() => {
    if (open) { if (dialog.current?.showModal) dialog.current.showModal(); else dialog.current?.setAttribute('open', ''); }
  }, [open]);
  const rows = choices.map(sensor => <label className="check" key={sensor.sensor_id}><input type="checkbox" aria-label={sensor.name} checked={selected.includes(sensor.sensor_id)} onChange={event => { onSelectionChange(); setSelected(current => event.target.checked ? [...current, sensor.sensor_id] : current.filter(id => id !== sensor.sensor_id)); }}/><span>{sensor.name}{open && <small>{sensor.sensor_id}</small>}</span></label>);
  return <fieldset className="sensor-selection" aria-label="Sensors"><legend>Sensors <button type="button" ref={invoker} onClick={() => setOpen(true)}>Choose sensors</button></legend>{selected.map(id => <input key={id} type="hidden" name="sensor_ids" value={id}/>)}<span>{selected.length} selected</span>{small && !open && rows}{query.error && <p role="alert">{query.error.message}<button type="button" onClick={() => query.refetch()}>Retry sensors</button></p>}{open && <dialog ref={dialog} className="sensor-selector-dialog" aria-label="Choose sensors" onCancel={event => { event.preventDefault(); close(); }}><h2>Choose sensors</h2><p>{selected.length} selected across all pages</p>{query.isPending ? <p role="status">Loading sensors…</p> : rows}<SensorPagination data={query.data} onPage={setPage}/><button type="button" onClick={close}>Done choosing sensors</button></dialog>}</fieldset>;
}
