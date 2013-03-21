-- add extra constraint to emailaddress table
ALTER TABLE emailaddress
    ADD CONSTRAINT emailaddress__is_linked__chk CHECK (((person IS NOT NULL) OR (account IS NOT NULL)));
