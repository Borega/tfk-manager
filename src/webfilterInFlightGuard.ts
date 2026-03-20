export type InFlightRef<T> = {
  current: Promise<T> | null;
};

export function runWithInFlightGuard<T>(
  inFlightRef: InFlightRef<T>,
  fetchTask: () => Promise<T>,
): Promise<T> {
  if (inFlightRef.current) {
    return inFlightRef.current;
  }

  const pending = (async () => fetchTask())()
    .finally(() => {
      if (inFlightRef.current === pending) {
        inFlightRef.current = null;
      }
    });

  inFlightRef.current = pending;
  return pending;
}
