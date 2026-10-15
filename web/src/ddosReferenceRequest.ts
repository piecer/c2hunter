export function ddosReferenceParameters(form: FormData): Record<string, unknown> {
  const mode = form.get('ddos_reference_mode');
  if (mode === null || mode === 'inherit') return {};
  if (mode === 'clear') return { ddos_normal_reference: null };
  const job_id = form.get('ddos_reference_job');
  const dataset_id = form.get('ddos_reference_dataset');
  if (mode !== 'select' || typeof job_id !== 'string' || !job_id || job_id.length > 200 || typeof dataset_id !== 'string' || !dataset_id || dataset_id.length > 200) throw new Error('Select a normal dataset / 정상 데이터셋을 선택하세요');
  return { ddos_normal_reference: { job_id, dataset_id } };
}
