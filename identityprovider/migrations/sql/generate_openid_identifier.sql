--! Copyright 2010 Canonical Ltd.  This software is licensed under the
--! GNU Affero General Public License version 3 (see the file LICENSE).

--! __init__
DROP LANGUAGE IF EXISTS plpythonu CASCADE;
CREATE LANGUAGE plpythonu;

--! generate_openid_identifier
CREATE OR REPLACE FUNCTION generate_openid_identifier()
  RETURNS text AS
$BODY$
    from random import choice

    # Non display confusing characters.
    chars = '34678bcdefhkmnprstwxyzABCDEFGHJKLMNPQRTWXY'

    # Character length of tokens. Can be increased, decreased or even made
    # random - Launchpad does not care. 7 means it takes 40 bytes to store
    # a null-terminated Launchpad identity URL on the current domain name.
    length=7

    loop_count = 0
    while loop_count < 20000:
        # Generate a random openid_identifier
        oid = ''.join(choice(chars) for count in range(length))

        # Check if the oid is already in the db, although this is pretty
        # unlikely
        rv = plpy.execute("""
            SELECT COUNT(*) AS num FROM Account WHERE openid_identifier = '%%s'
            """ %% oid, 1)
        if rv[0]['num'] == 0:
            return oid
        loop_count += 1
        if loop_count == 1:
            plpy.warning(
                'Clash generating unique openid_identifier. '
                'Increase length if you see this warning too much.')
    plpy.error(
        "Unable to generate unique openid_identifier. "
        "Need to increase length of tokens.")
$BODY$
  LANGUAGE 'plpythonu' VOLATILE
  COST 100;
