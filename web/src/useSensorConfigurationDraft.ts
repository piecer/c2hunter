import { useLayoutEffect, useRef, useSyncExternalStore } from 'react';
import { QueryClient, useQueryClient } from '@tanstack/react-query';
import { api } from './api';
import { captureAuthentication, currentAuthentication, type Authentication } from './authentication';
import { sensorRequiredError } from './sensorRequiredError';

export type DraftSource = { interface: string; direction: string; bpf_filter: string; enabled: boolean; store_pcap?: boolean };
type Configuration = { config_version: number; capture_sources: DraftSource[]; internal_networks: string[] };
type State = Configuration & { pending: boolean; saved: boolean; dirty: boolean; error?: Error };
type Owner = { state: State; listeners: Set<() => void> };
type Scope = { authority: Authentication; owners: Map<string, Owner> };
const scopes = new WeakMap<QueryClient, Scope>();
const copy = (body: Configuration): Configuration => ({ config_version: body.config_version, capture_sources: body.capture_sources.map(source => ({ interface: source.interface, direction: source.direction, bpf_filter: source.bpf_filter, enabled: source.enabled, store_pcap: source.store_pcap ?? false })), internal_networks: [...body.internal_networks] });
function publish(owner: Owner, changes: Partial<State>) {
  owner.state = { ...owner.state, ...changes };
  owner.listeners.forEach(listener => listener());
}

function validConfiguration(value: unknown): value is Configuration {
  if (!value || typeof value !== 'object') return false;
  const body = value as Configuration;
  return Number.isSafeInteger(body.config_version) && body.config_version > 0
    && Array.isArray(body.capture_sources) && body.capture_sources.length > 0 && body.capture_sources.length <= 128
    && body.capture_sources.every(source => source && typeof source.interface === 'string' && !!source.interface.trim() && typeof source.direction === 'string' && ['INBOUND', 'OUTBOUND', 'BIDIRECTIONAL'].includes(source.direction) && typeof source.bpf_filter === 'string' && typeof source.enabled === 'boolean' && (source.store_pcap === undefined || typeof source.store_pcap === 'boolean'))
    && Array.isArray(body.internal_networks) && body.internal_networks.length > 0 && body.internal_networks.length <= 1024
    && body.internal_networks.every(value => typeof value === 'string' && !!value.trim());
}

export function useSensorConfigurationDraft(sensorId: string, initial: Configuration) {
  const client = useQueryClient();
  const authority = captureAuthentication();
  let scope = scopes.get(client);
  if (!scope || scope.authority.epoch !== authority.epoch) {
    scope = { authority, owners: new Map() }; scopes.set(client, scope);
  }
  const refused = useRef<Owner>({ state: { ...copy(initial), pending: false, saved: false, dirty: false, error: new Error('16 configuration owners contain unsaved, unresolved, active or pending work. Open a retained sensor and save successfully, or reload latest configuration to discard its draft; then return here. Pending operations must finish first.') }, listeners: new Set() });
  let entry = scope.owners.get(sensorId);
  if (!entry && scope.owners.size >= 16) {
    // A closed editor can still own unsaved or unresolved work.
    const idle = [...scope.owners].find(([, candidate]) => !candidate.state.pending && !candidate.state.dirty && !candidate.state.error && candidate.listeners.size === 0);
    if (idle) scope.owners.delete(idle[0]);
  }
  if (!entry && scope.owners.size < 16) {
    entry = { state: { ...copy(initial), pending: false, saved: false, dirty: false }, listeners: new Set() };
    scope.owners.set(sensorId, entry);
  }
  const owner = entry ?? refused.current, capturedScope = scope;
  const live = useRef<Owner | undefined>(owner);
  useLayoutEffect(() => { live.current = owner; return () => { live.current = undefined; }; }, [owner]);
  const state = useSyncExternalStore(listener => { owner.listeners.add(listener); return () => owner.listeners.delete(listener); }, () => owner.state);
  const owned = () => currentAuthentication(capturedScope.authority) && scopes.get(client) === capturedScope && capturedScope.owners.get(sensorId) === owner;
  const admitted = () => live.current === owner && owned() && !owner.state.pending;
  const update = (changes: Partial<Configuration>) => { if (admitted()) publish(owner, { ...changes, dirty: true, saved: false }); };
  const save = async () => {
    if (!admitted()) return;
    const error = sensorRequiredError(owner.state.capture_sources, owner.state.internal_networks);
    if (error) { publish(owner, { error: new Error(error), saved: false }); return; }
    const body = copy(owner.state);
    body.internal_networks = body.internal_networks.map(value => value.trim());
    publish(owner, { pending: true, saved: false });
    try {
      const result = await api.put<Configuration>(`/sensors/${encodeURIComponent(sensorId)}/configuration`, body);
      if (!owned()) return;
      if (!validConfiguration(result) || result.config_version <= body.config_version) throw new Error('Configuration save is unconfirmed. Reload latest configuration before retrying.');
      publish(owner, { ...copy(result), dirty: false, saved: true, error: undefined });
    } catch (error) {
      if (owned()) publish(owner, { error: error instanceof Error ? error : new Error('Unable to save configuration'), saved: false });
    } finally { if (owned()) publish(owner, { pending: false }); }
  };
  const reload = async () => {
    if (!admitted()) return;
    publish(owner, { pending: true, saved: false });
    try {
      const result = await api.get<Configuration>(`/sensors/${encodeURIComponent(sensorId)}/configuration`);
      if (!owned()) return;
      if (!validConfiguration(result)) throw new Error('Configuration reload is unconfirmed.');
      publish(owner, { ...copy(result), dirty: false, error: undefined });
    } catch (error) {
      if (owned()) publish(owner, { error: error instanceof Error ? error : new Error('Unable to reload configuration') });
    } finally { if (owned()) publish(owner, { pending: false }); }
  };
  // Refusal is read-only, not missing server data and not an editable empty draft.
  return { ...state, ...(!entry ? copy(initial) : {}), available: !!entry, update, save, reload };
}
