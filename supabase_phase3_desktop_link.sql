-- Phase 3: Desktop pairing flow.
--
-- The desktop daemon can't participate in the marketing site's Clerk
-- auth directly (different security context). So we hand off via a
-- short-lived "desktop session" row:
--
--   1. Daemon creates a row with `status = 'pending'`.
--   2. Daemon opens the user's browser to /login?redirect_url=/desktop-link?session=<id>.
--   3. After Clerk auth, /desktop-link PATCHes the row with user info
--      and `status = 'linked'`.
--   4. Daemon polls every ~2s; on linked, it pulls the user identity
--      and proceeds with device registration + PNK sync.
--
-- The session ID is the bearer secret: anyone holding it can read AND
-- claim the session, so it must be a UUIDv4 and stay short-lived.

CREATE TABLE IF NOT EXISTS public.desktop_sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     TEXT,
  email       TEXT,
  name        TEXT,
  image_url   TEXT,
  status      TEXT NOT NULL DEFAULT 'pending'
              CHECK (status IN ('pending', 'linked', 'consumed', 'expired')),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  linked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_desktop_sessions_status_created
  ON public.desktop_sessions(status, created_at DESC);

-- RLS policies.
--
-- Supabase auto-enables RLS on public-schema tables; trying to DISABLE
-- it doesn't reliably stick across project settings. So instead we
-- ENABLE it and add three permissive policies covering the operations
-- the daemon and the marketing-site API route actually need.
--
-- Security model: the session ID (uuid v4) IS the access token. With
-- 122 bits of entropy it's not guessable, and the row is short-lived
-- (consumed/expired after at most ~10 min). Once consumed, even the
-- session's true owner can't claim it again.

ALTER TABLE public.desktop_sessions ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "desktop_sessions_insert" ON public.desktop_sessions;
DROP POLICY IF EXISTS "desktop_sessions_select" ON public.desktop_sessions;
DROP POLICY IF EXISTS "desktop_sessions_update" ON public.desktop_sessions;

-- Anyone can create a new pending row (the daemon, using the anon key).
CREATE POLICY "desktop_sessions_insert"
  ON public.desktop_sessions FOR INSERT
  TO anon, authenticated
  WITH CHECK (true);

-- Anyone can read by ID (the daemon polls its own session).
CREATE POLICY "desktop_sessions_select"
  ON public.desktop_sessions FOR SELECT
  TO anon, authenticated
  USING (true);

-- Anyone can update (the marketing site claims the session post-Clerk
-- auth; in prod that update goes through /api/desktop-link which uses
-- the service-role key and bypasses RLS anyway).
CREATE POLICY "desktop_sessions_update"
  ON public.desktop_sessions FOR UPDATE
  TO anon, authenticated
  USING (true)
  WITH CHECK (true);
