
-- =========================================================
-- ONELINE: IDENTITY AND PLATFORM ACCESS
-- Migration 1
-- =========================================================

-- 1. User profiles
-- Connected to Supabase Auth users.

CREATE TABLE public.profiles (
    id UUID PRIMARY KEY
        REFERENCES auth.users (id)
        ON DELETE CASCADE,

    full_name TEXT NOT NULL,

    avatar_path TEXT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT profiles_full_name_not_empty
        CHECK (LENGTH(TRIM(full_name)) > 0)
);

-- 2. Platform roles
-- Platform roles are separate from organization memberships.

CREATE TABLE public.platform_roles (
    user_id UUID NOT NULL
        REFERENCES public.profiles (id)
        ON DELETE CASCADE,

    role TEXT NOT NULL
        CHECK (role IN ('admin', 'super_admin')),

    granted_by UUID
        REFERENCES public.profiles (id)
        ON DELETE SET NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (user_id, role)
);

-- 3. Enable Row Level Security

ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.platform_roles ENABLE ROW LEVEL SECURITY;

-- 4. Profiles: users can read their own profile.

CREATE POLICY "Users can read own profile"
ON public.profiles
FOR SELECT
TO authenticated
USING ((SELECT auth.uid()) = id);

-- 5. Profiles: users can update their own profile.
-- Role information is not stored in this table.

CREATE POLICY "Users can update own profile"
ON public.profiles
FOR UPDATE
TO authenticated
USING ((SELECT auth.uid()) = id)
WITH CHECK ((SELECT auth.uid()) = id);

-- 6. Platform roles: users can read their own assigned roles.

CREATE POLICY "Users can read own platform roles"
ON public.platform_roles
FOR SELECT
TO authenticated
USING ((SELECT auth.uid()) = user_id);

-- Intentionally no client INSERT, UPDATE, or DELETE policies
-- for platform_roles.
-- Role assignment will be handled through a trusted
-- administrative process in a later migration.
