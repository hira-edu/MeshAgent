#ifndef MESH_MACOS_UPDATE_H
#define MESH_MACOS_UPDATE_H
/* One executable retains its launchd job, argv, and adjacent identity files.
 * Return 0 on success, -1 with errno on failure. Recover returns 1 when the
 * incumbent was restored and the caller must exec it before starting work, or
 * 2 when the new executable starts its first uncommitted trial. */
int MeshMacUpdate_Preflight(const char* executable, const char* staged);
int MeshMacUpdate_Apply(const char* executable, const char* staged);
int MeshMacUpdate_Recover(const char* executable, int forceRollback);
int MeshMacUpdate_Commit(const char* executable);
#endif
