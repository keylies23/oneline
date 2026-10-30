
-- =========================================================
-- ONELINE: EVENTS AND EVENT CATEGORIES
-- Migration 7
-- =========================================================

-- ---------------------------------------------------------
-- 1. EVENTS TABLE
-- ---------------------------------------------------------

CREATE TABLE public.events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    title TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,

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

    location_name TEXT,
    location_address TEXT,

    start_date DATE NOT NULL,
    end_date DATE NOT NULL,

    registration_opens_at TIMESTAMPTZ,
    registration_closes_at TIMESTAMPTZ,

    publication_status TEXT NOT NULL DEFAULT 'draft'
        CHECK (
            publication_status IN (
                'draft',
                'published',
                'archived'
            )
        ),

    execution_status TEXT NOT NULL DEFAULT 'upcoming'
        CHECK (
            execution_status IN (
                'upcoming',
                'ongoing',
                'completed',
                'cancelled'
            )
        ),

    created_by UUID NOT NULL
        REFERENCES public.profiles (id)
        ON DELETE RESTRICT,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT events_title_not_empty
        CHECK (LENGTH(TRIM(title)) > 0),

    CONSTRAINT events_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),

    CONSTRAINT events_dates_valid
        CHECK (end_date >= start_date),

    CONSTRAINT events_registration_dates_valid
        CHECK (
            registration_opens_at IS NULL
            OR registration_closes_at IS NULL
            OR registration_closes_at >= registration_opens_at
        )
);

-- ---------------------------------------------------------
-- 2. EVENT CATEGORIES TABLE
-- ---------------------------------------------------------

CREATE TABLE public.event_categories (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    event_id UUID NOT NULL
        REFERENCES public.events (id)
        ON DELETE CASCADE,

    name TEXT NOT NULL,
    slug TEXT NOT NULL,

    gender_category TEXT NOT NULL DEFAULT 'open'
        CHECK (
            gender_category IN (
                'male',
                'female',
                'mixed',
                'open'
            )
        ),

    min_age INTEGER,
    max_age INTEGER,

    max_teams INTEGER,

    registration_fee NUMERIC(14,2) NOT NULL DEFAULT 0,

    is_active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT event_categories_name_not_empty
        CHECK (LENGTH(TRIM(name)) > 0),

    CONSTRAINT event_categories_slug_format
        CHECK (slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),

    CONSTRAINT event_categories_unique_slug
        UNIQUE (event_id, slug),

    CONSTRAINT event_categories_age_valid
        CHECK (
            (min_age IS NULL OR min_age >= 0)
            AND
            (max_age IS NULL OR max_age >= 0)
            AND
            (
                min_age IS NULL
                OR max_age IS NULL
                OR max_age >= min_age
            )
        ),

    CONSTRAINT event_categories_max_teams_valid
        CHECK (max_teams IS NULL OR max_teams > 0),

    CONSTRAINT event_categories_fee_valid
        CHECK (registration_fee >= 0)
);

-- ---------------------------------------------------------
-- 3. INDEXES
-- ---------------------------------------------------------

CREATE INDEX idx_events_sport
    ON public.events (sport);

CREATE INDEX idx_events_start_date
    ON public.events (start_date);

CREATE INDEX idx_events_publication_status
    ON public.events (publication_status);

CREATE INDEX idx_events_execution_status
    ON public.events (execution_status);

CREATE INDEX idx_events_created_by
    ON public.events (created_by);

CREATE INDEX idx_event_categories_event_id
    ON public.event_categories (event_id);

CREATE INDEX idx_event_categories_active
    ON public.event_categories (event_id, is_active);

-- ---------------------------------------------------------
-- 4. UPDATED_AT TRIGGERS
-- ---------------------------------------------------------

CREATE OR REPLACE FUNCTION public.handle_event_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = ''
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER on_event_updated
    BEFORE UPDATE ON public.events
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_event_updated_at();

CREATE TRIGGER on_event_category_updated
    BEFORE UPDATE ON public.event_categories
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_event_updated_at();

-- ---------------------------------------------------------
-- 5. ENABLE ROW LEVEL SECURITY
-- ---------------------------------------------------------

ALTER TABLE public.events
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE public.event_categories
    ENABLE ROW LEVEL SECURITY;

-- ---------------------------------------------------------
-- 6. EVENT POLICIES
-- ---------------------------------------------------------

-- Published events are publicly readable.
-- Admins can also read unpublished events.

CREATE POLICY "Public can view published events"
ON public.events
FOR SELECT
TO anon, authenticated
USING (
    publication_status = 'published'
    OR (
        (SELECT auth.uid()) IS NOT NULL
        AND public.is_platform_admin()
    )
);

-- Only platform admins can create events.

CREATE POLICY "Platform admins can create events"
ON public.events
FOR INSERT
TO authenticated
WITH CHECK (
    created_by = (SELECT auth.uid())
    AND public.is_platform_admin()
);

-- Only platform admins can update events.

CREATE POLICY "Platform admins can update events"
ON public.events
FOR UPDATE
TO authenticated
USING (
    public.is_platform_admin()
)
WITH CHECK (
    public.is_platform_admin()
);

-- Only platform admins can delete events.

CREATE POLICY "Platform admins can delete events"
ON public.events
FOR DELETE
TO authenticated
USING (
    public.is_platform_admin()
);

-- ---------------------------------------------------------
-- 7. EVENT CATEGORY POLICIES
-- ---------------------------------------------------------

-- Categories of published events are publicly readable.
-- Admins can also read categories of unpublished events.

CREATE POLICY "Public can view published event categories"
ON public.event_categories
FOR SELECT
TO anon, authenticated
USING (
    EXISTS (
        SELECT 1
        FROM public.events AS e
        WHERE e.id = event_categories.event_id
          AND e.publication_status = 'published'
    )
    OR (
        (SELECT auth.uid()) IS NOT NULL
        AND public.is_platform_admin()
    )
);

-- Only platform admins can create event categories.

CREATE POLICY "Platform admins can create event categories"
ON public.event_categories
FOR INSERT
TO authenticated
WITH CHECK (
    public.is_platform_admin()
);

-- Only platform admins can update event categories.

CREATE POLICY "Platform admins can update event categories"
ON public.event_categories
FOR UPDATE
TO authenticated
USING (
    public.is_platform_admin()
)
WITH CHECK (
    public.is_platform_admin()
);

-- Only platform admins can delete event categories.

CREATE POLICY "Platform admins can delete event categories"
ON public.event_categories
FOR DELETE
TO authenticated
USING (
    public.is_platform_admin()
);
