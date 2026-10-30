
-- =========================================================
-- ONELINE: HARDEN ORGANIZATION MEMBERSHIP POLICIES
-- Migration 4
-- =========================================================

-- Remove the previous permissive membership insert policy.
DROP POLICY "Owners and managers can add members"
ON public.organization_memberships;

-- Owners can add managers and staff.
-- Managers can only add staff.
-- Platform admins can add any permitted membership role.

CREATE POLICY "Authorized users can add organization members"
ON public.organization_memberships
FOR INSERT
TO authenticated
WITH CHECK (
    public.is_platform_admin()

    OR (
        public.has_org_role(
            organization_id,
            ARRAY['owner']
        )
        AND role IN ('manager', 'staff')
    )

    OR (
        public.has_org_role(
            organization_id,
            ARRAY['manager']
        )
        AND role = 'staff'
    )
);
