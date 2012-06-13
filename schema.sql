drop table if exists user;
create table user (
  user_id integer primary key autoincrement,
  username string not null,
  email string not null,
  pw_hash string not null,
  insecure integer,
);

drop table if exists follower;
create table follower (
  who_id integer,
  whom_id integer,
  default_to_sticky integer not null
);

drop table if exists registered_clients;
create table registered_clients (
  client_id integer primary key autoincrement,
  user_id integer not null,
  hostname string not null,
  port integer not null,
  password string not null,
  date_added string not null,
  date_modified string not null
);

drop table if exists message;
create table message (
  message_id integer primary key autoincrement,
  author_id integer not null,
  text string not null,
  pub_date integer,
  notified integer default 0
);
