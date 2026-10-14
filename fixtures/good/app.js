export async function list(vcs) {
  return vcs.data('expenses').list({ limit: 50 });
}
