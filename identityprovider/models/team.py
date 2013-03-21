# Copyright 2010 Canonical Ltd.  This software is licensed under the
# GNU Affero General Public License version 3 (see the file LICENSE).

from django.db import models

from identityprovider.const import PERSON_VISIBILITY_PUBLIC
from identityprovider.models import Person

__all__ = (
    'get_team_memberships_for_user',
    'TeamParticipation',
)


def get_team_memberships_for_user(team_names, user, include_private=False):
    teams = Person.objects.filter(
        name__in=team_names,      # All team names provided
        teamowner__isnull=False,  # Only teams
    )
    if not include_private:
        teams = teams.filter(
            visibility=PERSON_VISIBILITY_PUBLIC)
    # Only teams in which the user is a member, which can be either through
    # direct membership or by being a team owner.
    teams = teams.filter(
        models.Q(team_participations__person=user.person) |
        models.Q(teamowner=models.F('id')),
    )
    # By default it's a query set result, not a true list
    return list(teams.values_list('name', flat=True))


class TeamParticipation(models.Model):
    team = models.ForeignKey(Person, db_column='team', null=True,
                             related_name='team_participations')
    person = models.ForeignKey(Person, db_column='person', null=True)

    class Meta:
        app_label = 'identityprovider'
        db_table = u'lp_teamparticipation'
        unique_together = ('team', 'person')

    def __unicode__(self):
        return "%s in %s" % (unicode(self.person), unicode(self.team))
