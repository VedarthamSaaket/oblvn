create table if not exists smart_history (
  serial varchar(128) not null,
  captured_on date not null,
  captured_at timestamptz not null default now(),
  org_id uuid references organisations(id) on delete cascade,
  snapshot jsonb not null,
  primary key (serial, captured_on)
);

create index if not exists smart_history_serial_time_idx on smart_history(serial, captured_at desc);

alter table smart_history enable row level security;
