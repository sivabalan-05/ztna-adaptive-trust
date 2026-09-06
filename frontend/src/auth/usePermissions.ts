import { useMemo } from "react";
import { useAuth } from "./AuthContext";

/**
 * What the signed-in role may actually do.
 *
 * The server is the authority — every route re-checks the permission — but the
 * console must not offer a control the caller's role will be refused for. A
 * security_analyst seeing an "Approve device" button that always fails is a
 * worse experience than not seeing it at all.
 */
export function usePermissions() {
  const { me } = useAuth();

  return useMemo(() => {
    const granted = new Set(me?.permissions ?? []);
    const isAdmin = Boolean(me?.is_admin);
    return {
      isAdmin,
      isOperator: isAdmin || me?.role === "security_analyst",
      can: (permission: string) => isAdmin || granted.has(permission),
    };
  }, [me]);
}
