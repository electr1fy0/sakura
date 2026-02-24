create extension citext if not exists;

create table if not exists users(
    id uuid primary key default gen_random_uuid(),
    email citext unique not null,
    password_hash text,
    created_at timestamptz not null default now()
);

create table if not exists clients (
    id uuid primary key default gen_random_uuid(),
    secret text,
    is_public boolean not null,
    constraint public_and_null check (
        (is_public and secret is null)
    or
        (not is_public and secret is not null)
    )
);

create table if not exists redirect_uris (
    id uuid primary key default gen_random_uuid(),
    client_id uuid not null references clients(id),
    uri text not null,

    unique(client_id, uri),
    unique(id, client_id)
);


create table if not exists authorization_codes (
    code text primary key,
    user_id uuid not null references users(id),
    client_id uuid not null,
    redirect_uri_id uuid not null,

    code_challenge text,
    code_challenge_method text,
    expires_at timestamptz not null,
    used boolean not null default false,
    created_at timestamptz default now(),

    check(code_challenge is null or code_challenge_method is not null),

    foreign key (redirect_uri_id, client_id)
    references redirect_uris(id, client_id)
);
