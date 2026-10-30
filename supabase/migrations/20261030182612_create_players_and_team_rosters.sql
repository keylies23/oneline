
-- =========================================================
-- ONELINE: PLAYERS AND TEAM ROSTERS
-- Migration 6
-- =========================================================

-- ---------------------------------------------------------
-- 1. HELPER FUNCTION
-- ---------------------------------------------------------

-- Check whether the current user can manage at least
-- one organization.

CREATE OR REPLACE FUNCTION public.can_manage_any_org()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT
        public.is_platform_admin()
        OR EXISTS (
            SELECT 1
            FROM public.organization_memberships AS om
            WHERE om.user_id = (SELECT auth.uid())
              AND om.status = 'active'
              AND om.role IN ('owner', 'manager')
        );
$$;

-- ---------------------------------------------------------
-- 2. PLAYERS TABLE
-- ---------------------------------------------------------

CREATE TABLE public.players (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    full_name TEXT NOT NULL,
    date_of_birth DATE,
    photo_path TEXT,

    created_by UUID NOT NULL
        DEFAULT auth.uid()
        REFERENCES public.profiles (id)
        ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT players_name_not_empty
        CHECK (LENGTH(TRIM(full_name)) > 0),

    CONSTRAINT players_date_of_birth_valid
        CHECK (
            date_of_birth IS NULL
            OR date_of_birth <= CURRENT_DATE
        )
);

-- ---------------------------------------------------------
-- 3. TEAM ROSTERS TABLE
-- ---------------------------------------------------------

CREATE TABLE public.team_rosters (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    team_id UUID NOT NULL
        REFERENCES public.teams (id)
        ON DELETE RESTRICT,

    player_id UUID NOT NULL
        REFERENCES public.players (id)
        ON DELETE RESTRICT,

    jersey_number INTEGER,
    position TEXT,

    joined_on DATE NOT NULL DEFAULT CURRENT_DATE,
    left_on DATE,

    created_by UUID NOT NULL
        DEFAULT auth.uid()
        REFERENCES public.profiles (id)
        ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT roster_jersey_number_valid
        CHECK (
            jersey_number IS NULL
            OR jersey_number BETWEEN 0 AND 999
        ),

    CONSTRAINT roster_dates_valid
        CHECK (
            left_on IS NULL
            OR left_on >= joined_on
        )
);

-- ---------------------------------------------------------
-- 4. INDEXES
-- ---------------------------------------------------------

CREATE INDEX idx_players_full_name
    ON public.players (full_name);

CREATE INDEX idx_players_created_by
    ON public.players (created_by);

CREATE INDEX idx_team_rosters_team_id
    ON public.team_rosters (team_id);

CREATE INDEX idx_team_rosters_player_id
    ON public.team_rosters (player_id);

-- A player can only have one active membership
-- in the same team.

CREATE UNIQUE INDEX unique_active_player_per_team
    ON public.team_rosters (team_id, player_id)
    WHERE left_on IS NULL;

-- Active jersey numbers must be unique within a team.

CREATE UNIQUE INDEX unique_active_jersey_number
    ON public.team_rosters (team_id, jersey_number)
    WHERE left_on IS NULL
      AND jersey_number IS NOT NULL;

-- ---------------------------------------------------------
-- 5. UPDATED_AT TRIGGER
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION public.handle_player_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_player_updated
    BEFORE UPDATE ON public.players
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_player_updated_at();

-- ---------------------------------------------------------
-- 6. ENABLE ROW LEVEL SECURITY
-- ---------------------------------------------------------

ALTER TABLE public.players
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.team_rosters
    ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------
-- 7. PLAYER POLICIES
-- ---------------------------------------------------------

-- Players can be viewed by platform admins and
-- active members of organizations whose teams
-- have registered the player.

CREATE POLICY "Authorized users can view players"
ON public.players
FOR SELECT
TO authenticated
USING (
    public.is_platform_admin()
    OR EXISTS (
        SELECT 1
        FROM public.team_rosters AS tr
        JOIN public.teams AS t
            ON t.id = tr.team_id
        WHERE tr.player_id = players.id
          AND public.has_org_role(
              t.organization_id,
              ARRAY['owner', 'manager', 'staff']
          )
    )
);

-- Only organization owners, managers, and
-- platform admins can create player records.

CREATE POLICY "Managers can create players"
ON public.players
FOR INSERT
TO authenticated
WITH CHECK (
    created_by = (SELECT auth.uid())
    AND public.can_manage_any_org()
);

-- Players can be updated by managers of organizations
-- whose teams have registered them.

CREATE POLICY "Managers can update players"
ON public.players
FOR UPDATE
TO authenticated
USING (
    public.is_platform_admin()
    OR EXISTS (
        SELECT 1
        FROM public.team_rosters AS tr
        JOIN public.teams AS t
            ON t.id = tr.team_id
        WHERE tr.player_id = players.id
          AND public.has_org_role(
              t.organization_id,
              ARRAY['owner', 'manager']
          )
    )
)
WITH CHECK (
    public.is_platform_admin()
    OR EXISTS (
        SELECT 1
        FROM public.team_rosters AS tr
        JOIN public.teams AS t
            ON t.id = tr.team_id
        WHERE tr.player_id = players.id
          AND public.has_org_role(
              t.organization_id,
              ARRAY['owner', 'manager']
          )
    )
);

-- No client-side DELETE policy for players.
-- Player identity and historical records are preserved.

-- ---------------------------------------------------------
-- 8. TEAM ROSTER POLICIES
-- ---------------------------------------------------------

-- Active organization members and platform admins
-- can view team rosters.

CREATE POLICY "Organization members can view team rosters"
ON public.team_rosters
FOR SELECT
TO authenticated
USING (
    public.is_platform_admin()
    OR EXISTS (
        SELECT 1
        FROM public.teams AS t
        WHERE t.id = team_rosters.team_id
          AND public.has_org_role(
              t.organization_id,
              ARRAY['owner', 'manager', 'staff']
          )
    )
);

-- Owners, managers, and platform admins
-- can register players into teams.

CREATE POLICY "Managers can add players to teams"
ON public.team_rosters
FOR INSERT
TO authenticated
WITH CHECK (
    created_by = (SELECT auth.uid())
    AND (
        public.is_platform_admin()
        OR EXISTS (
            SELECT 1
            FROM public.teams AS t
            WHERE t.id = team_rosters.team_id
              AND public.has_org_role(
                  t.organization_id,
                  ARRAY['owner', 'manager']
              )
        )
    )
);

-- Owners, managers, and platform admins
-- can update roster records, including left_on.

CREATE POLICY "Managers can update team rosters"
ON public.team_rosters
FOR UPDATE
TO authenticated
USING (
    public.is_platform_admin()
    OR EXISTS (
        SELECT 1
        FROM public.teams AS t
        WHERE t.id = team_rosters.team_id
          AND public.has_org_role(
              t.organization_id,
              ARRAY['owner', 'manager']
          )
    )
)
WITH CHECK (
    public.is_platform_admin()
    OR EXISTS (
        SELECT 1
        FROM public.teams AS t
        WHERE t.id = team_rosters.team_id
          AND public.has_org_role(
              t.organization_id,
              ARRAY['owner', 'manager']
          )
    )
);

-- No client-side DELETE policy.
-- Historical roster records must be preserved.
