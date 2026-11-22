/** Required checks cover retained pages; syntax and interface legality stay server-owned. */
export function sensorRequiredError(sources: { interface: string }[], networks: string[]): string | undefined {
  const source = sources.findIndex(value => !value.interface.trim());
  if (source >= 0) return `Interface name ${source + 1} is required.`;
  const network = networks.findIndex(value => !value.trim());
  if (network >= 0) return `Internal CIDR ${network + 1} is required.`;
  return undefined;
}
