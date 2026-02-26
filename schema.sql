create extension if not exists pgcrypto;
create extension if not exists citext;

create table if not exists users (
  id uuid primary key default gen_random_uuid(),
  email citext unique not null,
  password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists clients (
  id uuid primary key default gen_random_uuid(),
  secret_hash text,
  is_public boolean not null,
  constraint public_and_secret check (
    (is_public and secret_hash is null) or
    (not is_public and secret_hash is not null)
  )
);

create table if not exists redirect_uris (
  id uuid primary key default gen_random_uuid(),
  client_id uuid not null references clients(id) on delete cascade,
  uri text not null,
  unique (client_id, uri),
  unique (id, client_id)
);

create table if not exists authorization_codes (
  id uuid primary key default gen_random_uuid(),
  code_hash bytea not null unique, -- sha256(code)
  user_id uuid not null references users(id),
  client_id uuid not null,
  redirect_uri_id uuid not null,

  code_challenge text not null,
  code_challenge_method text not null,
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now(),

  check (code_challenge_method = 'S256'),
  check (expires_at > created_at),

  foreign key (redirect_uri_id, client_id)
    references redirect_uris(id, client_id)
);

create index if not exists authorization_codes_active_idx
  on authorization_codes (client_id, expires_at)
  where used_at is null;
