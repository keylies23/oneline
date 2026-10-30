
-- =========================================================
-- ONELINE: ORGANIZATIONS AND MEMBERSHIPS
-- Migration 3
-- =========================================================

-- ---------------------------------------------------------
-- 1. ORGANIZATIONS TABLE
-- ---------------------------------------------------------

CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,

    organization_type TEXT NOT NULL
        CHECK (
            organization_type IN (
                'school',
                'club',
                'community'
            )
        ),

    description TEXT,
    logo_path TEXT,

    created_by UUID NOT NULL
        REFERENCES public.profiles (id)
        ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT organizations_name_not_empty
        CHECK (LENGTH(TRIM(name)) > 0),

    CONSTRAINT organizations_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$')
);

-- ---------------------------------------------------------
-- 2. ORGANIZATION MEMBERSHIPS TABLE
-- ---------------------------------------------------------

CREATE TABLE public.organization_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    organization_id UUID NOT NULL
        REFERENCES public.organizations (id)
        ON DELETE CASCADE,

    user_id UUID NOT NULL
        REFERENCES public.profiles (id)
        ON DELETE CASCADE,

    role TEXT NOT NULL
        CHECK (role IN ('owner', 'manager', 'staff')),

    status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended')),

    joined_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT unique_organization_member
        UNIQUE (organization_id, user_id)
);

-- ---------------------------------------------------------
-- 3. INDEXES
-- ---------------------------------------------------------

CREATE INDEX idx_organizations_created_by
    ON public.organizations (created_by);

CREATE INDEX idx_organizations_type
    ON public.organizations (organization_type);

CREATE INDEX idx_memberships_user_id
    ON public.organization_memberships (user_id);

CREATE INDEX idx_memberships_organization_id
    ON public.organization_memberships (organization_id);

CREATE INDEX idx_memberships_active_user
    ON public.organization_memberships (user_id, status);

-- ---------------------------------------------------------
-- 4. HELPER FUNCTIONS
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION public.has_org_role(
    p_organization_id UUID,
    p_roles TEXT[]
)
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.organization_memberships AS om
        WHERE om.organization_id = p_organization_id
          AND om.user_id = (SELECT auth.uid())
          AND om.status = 'active'
          AND om.role = ANY(p_roles)
    );
$$;

CREATE OR REPLACE FUNCTION public.is_platform_admin()
RETURNS BOOLEAN
LANGUAGE SQL
STABLE
SECURITY DEFINER
SET search_path = ''
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM public.platform_roles AS pr
        WHERE pr.user_id = (SELECT auth.uid())
          AND pr.role IN ('admin', 'super_admin')
    );
$$;

-- ---------------------------------------------------------
-- 5. AUTOMATIC OWNER MEMBERSHIP
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION public.handle_new_organization()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
BEGIN
    INSERT INTO public.organization_memberships (
        organization_id,
        user_id,
        role,
        status
    )
    VALUES (
        NEW.id,
        NEW.created_by,
        'owner',
        'active'
    );

    RETURN NEW;
END;
$$;

CREATE TRIGGER on_organization_created
    AFTER INSERT ON public.organizations
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_organization();

-- ---------------------------------------------------------
-- 6. ROW LEVEL SECURITY
-- ---------------------------------------------------------

ALTER TABLE public.organizations
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.organization_memberships
    ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------
-- 7. ORGANIZATION POLICIES
-- ---------------------------------------------------------

CREATE POLICY "Members and admins can view organizations"
ON public.organizations
FOR SELECT
TO authenticated
USING (
    public.has_org_role(id, ARRAY['owner', 'manager', 'staff'])
    OR public.is_platform_admin()
);

CREATE POLICY "Users can create organizations"
ON public.organizations
FOR INSERT
TO authenticated
WITH CHECK (
    created_by = (SELECT auth.uid())
);

CREATE POLICY "Owners managers and admins can update organizations"
ON public.organizations
FOR UPDATE
TO authenticated
USING (
    public.has_org_role(id, ARRAY['owner', 'manager'])
    OR public.is_platform_admin()
)
WITH CHECK (
    public.has_org_role(id, ARRAY['owner', 'manager'])
    OR public.is_platform_admin()
);

CREATE POLICY "Owners and admins can delete organizations"
ON public.organizations
FOR DELETE
TO authenticated
USING (
    public.has_org_role(id, ARRAY['owner'])
    OR public.is_platform_admin()
);

-- ---------------------------------------------------------
-- 8. MEMBERSHIP POLICIES
-- ---------------------------------------------------------

CREATE POLICY "Organization members can view memberships"
ON public.organization_memberships
FOR SELECT
TO authenticated
USING (
    user_id = (SELECT auth.uid())
    OR public.has_org_role(
        organization_id,
        ARRAY['owner', 'manager', 'staff']
    )
    OR public.is_platform_admin()
);

CREATE POLICY "Owners and managers can add members"
ON public.organization_memberships
FOR INSERT
TO authenticated
WITH CHECK (
    public.has_org_role(
        organization_id,
        ARRAY['owner', 'manager']
    )
    OR public.is_platform_admin()
);

-- No client-side UPDATE or DELETE policies yet.
-- Membership changes will use controlled server-side operations.
