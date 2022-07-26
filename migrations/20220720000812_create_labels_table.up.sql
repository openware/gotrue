-- adds lables table 

CREATE TABLE IF NOT EXISTS auth.labels (
	id          :bigint          NOT NULL
	user_id     :uuid            NOT NULL
	label       enum(`email`,`phone`,`profile`,`document`)  NOT NULL
	state       enum(`unverified`,`pending`,`verified`,`expired`)   NOT NULL default `unverified`
	created_at  timestamptz     NOT NULL
	updated_at  timestamptz     NOT NULL
	CONSTRAINT labels_pkey PRIMARY KEY (id),
	CONSTRAINT labels_user_id_fkey FOREIGN KEY (user_id) REFERENCES auth.users(id) ON DELETE CASCADE
);
COMMENT ON TABLE auth.labels is 'Auth: Stores labels associated to a user.';
