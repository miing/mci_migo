-- add custom indexes
CREATE INDEX openidauthorization_account_troot_expires_client_id ON openidauthorization USING btree (account, trust_root, date_expires, client_id);
CREATE UNIQUE INDEX openidauthorization_account_trust_root ON openidauthorization USING btree (account, trust_root) WHERE (client_id IS NULL);
CREATE UNIQUE INDEX openidauthorization_account_client_id_trust_root ON openidauthorization USING btree (account, client_id, trust_root) WHERE (client_id IS NOT NULL);
