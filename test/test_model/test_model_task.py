# -*- coding: utf8 -*-
# This file is part of PyBossa.
#
# Copyright (C) 2013 SF Isle of Man Limited
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

from base import model, db
from nose.tools import assert_raises
from sqlalchemy.exc import IntegrityError


class TestModelTask:

    def setUp(self):
        model.rebuild_db()

    def tearDown(self):
        db.session.remove()


    def test_task_errors(self):
        """Test TASK model errors."""
        user = model.User(
            email_addr="john.doe@example.com",
            name="johndoe",
            fullname="John Doe",
            locale="en")
        db.session.add(user)
        db.session.commit()
        user = db.session.query(model.User).first()
        app = model.App(
            name='Application',
            short_name='app',
            description='desc',
            owner_id=user.id)
        db.session.add(app)
        db.session.commit()

        task = model.Task(app_id=None)
        db.session.add(task)
        assert_raises(IntegrityError, db.session.commit)
        db.session.rollback()
