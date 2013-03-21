-- add custom indexes
CREATE INDEX emailaddress_account_status ON emailaddress USING btree (account, status);
CREATE INDEX emailaddress_person_status ON emailaddress USING btree (person, status);

-- add case specific indexes for emails
CREATE UNIQUE INDEX emailaddress__lower_email__key ON emailaddress USING btree (lower(email));
CREATE UNIQUE INDEX fyiyfchafdba ON emailaddress USING btree (upper(email));
