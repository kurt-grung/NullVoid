import { createContext, useContext, useState, useCallback, type ReactNode } from 'react'

interface OrgTeamContextValue {
  organizationId: string | null
  teamId: string | null
  setOrganizationId: (id: string | null) => void
  setTeamId: (id: string | null) => void
}

const OrgTeamContext = createContext<OrgTeamContextValue | null>(null)

export function OrgTeamProvider({ children }: { children: ReactNode }) {
  const [organizationId, setOrganizationId] = useState<string | null>(null)
  const [teamId, setTeamId] = useState<string | null>(null)

  const setOrg = useCallback((id: string | null) => {
    setOrganizationId(id)
    setTeamId(null)
  }, [])

  return (
    <OrgTeamContext.Provider
      value={{
        organizationId,
        teamId,
        setOrganizationId: setOrg,
        setTeamId,
      }}
    >
      {children}
    </OrgTeamContext.Provider>
  )
}

export function useOrgTeam() {
  const ctx = useContext(OrgTeamContext)
  if (!ctx) throw new Error('useOrgTeam must be used within OrgTeamProvider')
  return ctx
}
