-- adds lables table 

CREATE TYPE label_name AS ENUM ('email','phone','profile','document');
CREATE TYPE label_state AS ENUM ('unverified','pending','verified','expired');

CREATE TABLE IF NOT EXISTS auth.labels (
	id          bigint          NOT NULL,
	user_id     uuid            NOT NULL,
	label       label_name  NOT NULL,
	state       label_state   NOT NULL DEFAULT 'unverified',
	created_at  timestamptz     NOT NULL,
	updated_at  timestamptz     NOT NULL,
	CONSTRAINT labels_pkey PRIMARY KEY (id),
	CONSTRAINT labels_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE auth.labels is 'Auth: Stores labels associated to a user.';
