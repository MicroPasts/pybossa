# -*- coding: utf8 -*-
# This file is part of PyBossa.
#
# Copyright (C) 2015 SF Isle of Man Limited
#
# PyBossa is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# PyBossa is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with PyBossa.  If not, see <http://www.gnu.org/licenses/>.
from flask import Blueprint, request, url_for, flash, redirect, session, request

from pybossa.core import dropbox

# This blueprint will be activated in core.py
# if the DROPBOX APP KEY and SECRET
# are available
blueprint = Blueprint('dropbox', __name__)


@blueprint.route('/')
def login():
    callback_url = url_for('.oauth_authorized', next=request.args.get('next'), _external=True)
    dicti = {'oauth_callback': callback_url}
    return dropbox.oauth.authorize(**dicti)

@blueprint.route('/revoke-access')
def logout():
    next_url = request.args.get('next') or url_for('home.home')
    if 'dropbox_token' in session:
        session.pop('dropbox_token')
    if 'dropbox_user' in session:
        session.pop('dropbox_user')
    return redirect(next_url)

@blueprint.route('/oauth-authorized')
def oauth_authorized():
    next_url = request.args.get('next')
    resp = dropbox.oauth.handle_oauth1_response()
    session.pop('dropbox_oauthtok', None)
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(next_url)
    dropbox_token = dict(oauth_token=resp['oauth_token'],
                        oauth_token_secret=resp['oauth_token_secret'])
    dropbox_user = dict(uid=resp['uid'])
    session['dropbox_token'] = dropbox_token
    session['dropbox_user'] = dropbox_user
    return redirect(next_url)
