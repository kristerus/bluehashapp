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
-- claim the session, so it must be a UUIDv4 and stay short-lived. We
-- mark sessions expired after 10 minutes.

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

-- The anon role needs to:
--   - INSERT  (daemon creates a pending session)
--   - SELECT  (daemon polls its own session by id)
--   - UPDATE  (marketing site claims the session post-auth; in production
--              that update should be performed by a service-role key
--              through the Next.js API route, not anon).
ALTER TABLE public.desktop_sessions DISABLE ROW LEVEL SECURITY;
GRANT SELECT, INSERT, UPDATE ON public.desktop_sessions TO anon;
