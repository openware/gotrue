-- adds asymmetric_address column to auth.users

alter table {{ index .Options "Namespace" }}.users
add column if not exists asymmetric_address varchar(255) null;
