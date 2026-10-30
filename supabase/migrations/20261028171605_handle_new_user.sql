
-- =========================================================
-- ONELINE: AUTOMATIC USER PROFILE CREATION
-- Migration 2
-- =========================================================

CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = ''
AS $$
DECLARE
    profile_name TEXT;
BEGIN
    profile_name := NULLIF(
        TRIM(NEW.raw_user_meta_data ->> 'full_name'),
        ''
    );

    IF profile_name IS NULL THEN
        profile_name := NULLIF(
            TRIM(NEW.raw_user_meta_data ->> 'name'),
            ''
        );
    END IF;

    IF profile_name IS NULL THEN
        profile_name := split_part(NEW.email, '@', 1);
    END IF;

    INSERT INTO public.profiles (
        id,
        full_name
    )
    VALUES (
        NEW.id,
        profile_name
    );

    RETURN NEW;
END;
$$;

-- Create the profile automatically when a new Auth user is created.

CREATE TRIGGER on_auth_user_created
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION public.handle_new_user();
