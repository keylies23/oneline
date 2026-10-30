
-- =========================================================
-- ONELINE: TEAMS
-- Migration 5
-- =========================================================

-- ---------------------------------------------------------
-- 1. TEAMS TABLE
-- ---------------------------------------------------------

CREATE TABLE public.teams (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    organization_id UUID NOT NULL
        REFERENCES public.organizations (id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,
    slug TEXT NOT NULL,

    sport TEXT NOT NULL
        CHECK (
            sport IN (
                'basketball',
                'volleyball',
                'futsal',
                'badminton',
                'tennis',
                'football'
            )
        ),

    description TEXT,
    logo_path TEXT,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_by UUID NOT NULL DEFAULT auth.uid()
        REFERENCES public.profiles (id)
        ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT teams_name_not_empty
        CHECK (LENGTH(TRIM(name)) > 0),

    CONSTRAINT teams_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),

    CONSTRAINT unique_team_slug_per_organization
        UNIQUE (organization_id, slug)
);

-- ---------------------------------------------------------
-- 2. INDEXES
-- ---------------------------------------------------------

CREATE INDEX idx_teams_organization_id
    ON public.teams (organization_id);

CREATE INDEX idx_teams_sport
    ON public.teams (sport);

CREATE INDEX idx_teams_active
    ON public.teams (organization_id, is_active);

-- ---------------------------------------------------------
-- 3. UPDATED_AT TRIGGER
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION public.handle_team_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_team_updated
    BEFORE UPDATE ON public.teams
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_team_updated_at();

-- ---------------------------------------------------------
-- 4. ROW LEVEL SECURITY
-- ---------------------------------------------------------

ALTER TABLE public.teams
    ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------
-- 5. TEAM POLICIES
-- ---------------------------------------------------------

-- Active organization members and platform admins
-- can view teams.

CREATE POLICY "Organization members can view teams"
ON public.teams
FOR SELECT
TO authenticated
USING (
    public.has_org_role(
        organization_id,
        ARRAY['owner', 'manager', 'staff']
    )
    OR public.is_platform_admin()
);

-- Owners, managers, and platform admins
-- can create teams.

CREATE POLICY "Owners and managers can create teams"
ON public.teams
FOR INSERT
TO authenticated
WITH CHECK (
    created_by = (SELECT auth.uid())
    AND (
        public.has_org_role(
            organization_id,
            ARRAY['owner', 'manager']
        )
        OR public.is_platform_admin()
    )
);

-- Owners, managers, and platform admins
-- can update teams.

CREATE POLICY "Owners and managers can update teams"
ON public.teams
FOR UPDATE
TO authenticated
USING (
    public.has_org_role(
        organization_id,
        ARRAY['owner', 'manager']
    )
    OR public.is_platform_admin()
)
WITH CHECK (
    public.has_org_role(
        organization_id,
        ARRAY['owner', 'manager']
    )
    OR public.is_platform_admin()
);

-- Owners and platform admins can delete teams.

CREATE POLICY "Owners and admins can delete teams"
ON public.teams
FOR DELETE
TO authenticated
USING (
    public.has_org_role(
        organization_id,
        ARRAY['owner']
    )
    OR public.is_platform_admin()
);
