-- Phase 4: Networks (shared encrypted spaces).
--
-- A "network" is a named shared space with its own symmetric Network
-- Key (NK). Files placed in the network are encrypted under that NK;
-- the NK is wrapped per-device-HIK and delivered via key_broker, the
-- same way the user's personal PNK already is.
--
-- Run on Supabase SQL Editor. Idempotent.

-- ============================================================
-- 1. networks
-- ============================================================
CREATE TABLE IF NOT EXISTS public.networks (
  id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name            TEXT NOT NULL,
  -- Decorative tag shown in the dashboard card (e.g. "AWS | us-east-2").
  -- Pure UX flavour — no infrastructure implication.
  region          TEXT,
  owner_user_id   TEXT NOT NULL,        -- Clerk user id of creator
  -- Bumped by the daemon whenever the NK is rotated (member removal,
  -- explicit rotate). All key_broker rows for this network carry the
  -- version of the NK they wrap. Old rows aren't deleted so members
  -- can still decrypt files encrypted with the previous NK.
  key_version     INTEGER NOT NULL DEFAULT 1,
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_networks_owner ON public.networks(owner_user_id);

-- ============================================================
-- 2. network_members
-- ============================================================
CREATE TABLE IF NOT EXISTS public.network_members (
  network_id    UUID NOT NULL REFERENCES public.networks(id) ON DELETE CASCADE,
  user_id       TEXT NOT NULL,
  role          TEXT NOT NULL DEFAULT 'member'
                CHECK (role IN ('admin', 'member')),
  joined_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (network_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_network_members_user
  ON public.network_members(user_id);

-- ============================================================
-- 3. network_invites
-- ============================================================
-- Email-based invites. We resolve the email to a user_id only at accept
-- time, so you can invite people who haven't signed up yet — they'll
-- see the invite the first time they hit the dashboard.
CREATE TABLE IF NOT EXISTS public.network_invites (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  network_id        UUID NOT NULL REFERENCES public.networks(id) ON DELETE CASCADE,
  inviter_user_id   TEXT NOT NULL,
  invited_email     TEXT NOT NULL,
  status            TEXT NOT NULL DEFAULT 'pending'
                    CHECK (status IN ('pending', 'accepted', 'declined', 'revoked', 'expired')),
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at        TIMESTAMPTZ NOT NULL DEFAULT (now() + INTERVAL '7 days'),
  responded_at      TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_invites_email_status
  ON public.network_invites(LOWER(invited_email), status);
CREATE INDEX IF NOT EXISTS idx_invites_network
  ON public.network_invites(network_id);

-- ============================================================
-- 4. key_broker.network_id
-- ============================================================
-- Tag each wrapped key with the network it belongs to. NULL = the
-- user's personal PNK (legacy / pre-networks behaviour).
ALTER TABLE public.key_broker
  ADD COLUMN IF NOT EXISTS network_id UUID
  REFERENCES public.networks(id) ON DELETE CASCADE;

CREATE INDEX IF NOT EXISTS idx_key_broker_network_target
  ON public.key_broker(network_id, target_device_id);

-- ============================================================
-- 5. RLS - permissive policies for daemon (anon) + signed-in users.
-- Real authz is in app code: the marketing-site API routes verify the
-- caller's Clerk session before mutating, and the daemon's writes are
-- gated by the session ID secret it generated.
-- ============================================================
ALTER TABLE public.networks         ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_members  ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.network_invites  ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "networks_all"         ON public.networks;
DROP POLICY IF EXISTS "network_members_all"  ON public.network_members;
DROP POLICY IF EXISTS "network_invites_all"  ON public.network_invites;

CREATE POLICY "networks_all" ON public.networks
  FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);

CREATE POLICY "network_members_all" ON public.network_members
  FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);

CREATE POLICY "network_invites_all" ON public.network_invites
  FOR ALL TO anon, authenticated USING (true) WITH CHECK (true);
