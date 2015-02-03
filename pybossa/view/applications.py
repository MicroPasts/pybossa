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

import time
import re
import json
import os
import math
import requests
from StringIO import StringIO

from flask import Blueprint, request, url_for, flash, redirect, abort, Response, current_app
from flask import render_template, make_response, session
from flask.ext.login import login_required, current_user
from flask.ext.babel import gettext
from rq import Queue

import pybossa.model as model
import pybossa.sched as sched

from pybossa.core import (uploader, signer, sentinel, json_exporter,
    csv_exporter, importer, flickr)
from pybossa.model.app import App
from pybossa.model.task import Task
from pybossa.util import Pagination, admin_required, get_user_id_or_ip
from pybossa.auth import require
from pybossa.cache import apps as cached_apps
from pybossa.cache import categories as cached_cat
from pybossa.cache import project_stats as stats
from pybossa.cache.helpers import add_custom_contrib_button_to
from pybossa.ckan import Ckan
from pybossa.extensions import misaka
from pybossa.cookies import CookieHandler
from pybossa.password_manager import ProjectPasswdManager
from pybossa.jobs import import_tasks
from pybossa.forms.applications_view_forms import *
from pybossa.importers import BulkImportException

from pybossa.core import project_repo, user_repo, task_repo, blog_repo, auditlog_repo
from pybossa.auditlogger import AuditLogger

blueprint = Blueprint('app', __name__)

auditlogger = AuditLogger(auditlog_repo, caller='web')
importer_queue = Queue('medium', connection=sentinel.master)
MAX_NUM_SYNCHRONOUS_TASKS_IMPORT = 200
HOUR = 60 * 60

def app_title(app, page_name):
    if not app:  # pragma: no cover
        return "Project not found"
    if page_name is None:
        return "Project: %s" % (app.name)
    return "Project: %s &middot; %s" % (app.name, page_name)


def app_by_shortname(short_name):
    app = cached_apps.get_app(short_name)
    if app:
        # Get owner
        owner = user_repo.get(app.owner_id)
        # Populate CACHE with the data of the app
        return (app,
                owner,
                cached_apps.n_tasks(app.id),
                cached_apps.n_task_runs(app.id),
                cached_apps.overall_progress(app.id),
                cached_apps.last_activity(app.id))

    else:
        cached_apps.delete_app(short_name)
        return abort(404)


@blueprint.route('/', defaults={'page': 1})
@blueprint.route('/page/<int:page>/', defaults={'page': 1})
def redirect_old_featured(page):
    """DEPRECATED only to redirect old links"""
    return redirect(url_for('.index', page=page), 301)


@blueprint.route('/published/', defaults={'page': 1})
@blueprint.route('/published/<int:page>/', defaults={'page': 1})
def redirect_old_published(page):  # pragma: no cover
    """DEPRECATED only to redirect old links"""
    category = project_repo.get_category()
    return redirect(url_for('.app_cat_index', category=category.short_name, page=page), 301)


@blueprint.route('/draft/', defaults={'page': 1})
@blueprint.route('/draft/<int:page>/', defaults={'page': 1})
def redirect_old_draft(page):
    """DEPRECATED only to redirect old links"""
    return redirect(url_for('.draft', page=page), 301)


@blueprint.route('/category/featured/', defaults={'page': 1})
@blueprint.route('/category/featured/page/<int:page>/')
def index(page):
    """List apps in the system"""
    if cached_apps.n_count('featured') > 0:
        return app_index(page, cached_apps.get_featured, 'featured',
                         True, False)
    else:
        categories = cached_cat.get_all()
        cat_short_name = categories[0].short_name
        return redirect(url_for('.app_cat_index', category=cat_short_name))


def app_index(page, lookup, category, fallback, use_count):
    """Show apps of app_type"""

    per_page = current_app.config['APPS_PER_PAGE']

    apps = lookup(category, page, per_page)
    count = cached_apps.n_count(category)

    data = []

    if fallback and not apps:  # pragma: no cover
        return redirect(url_for('.index'))

    pagination = Pagination(page, per_page, count)
    categories = cached_cat.get_all()
    # Check for pre-defined categories featured and draft
    featured_cat = model.category.Category(name='Featured',
                                  short_name='featured',
                                  description='Featured projects')
    if category == 'featured':
        active_cat = featured_cat
    elif category == 'draft':
        active_cat = model.category.Category(name='Draft',
                                    short_name='draft',
                                    description='Draft projects')
    else:
        active_cat = project_repo.get_category_by(short_name=category)

    # Check if we have to add the section Featured to local nav
    if cached_apps.n_count('featured') > 0:
        categories.insert(0, featured_cat)
    template_args = {
        "apps": apps,
        "title": gettext("Projects"),
        "pagination": pagination,
        "active_cat": active_cat,
        "categories": categories}

    if use_count:
        template_args.update({"count": count})
    return render_template('/applications/index.html', **template_args)


@blueprint.route('/category/draft/', defaults={'page': 1})
@blueprint.route('/category/draft/page/<int:page>/')
@login_required
@admin_required
def draft(page):
    """Show the Draft apps"""
    return app_index(page, cached_apps.get_draft, 'draft',
                     False, True)


@blueprint.route('/category/<string:category>/', defaults={'page': 1})
@blueprint.route('/category/<string:category>/page/<int:page>/')
def app_cat_index(category, page):
    """Show Apps that belong to a given category"""
    return app_index(page, cached_apps.get, category, False, True)


@blueprint.route('/new', methods=['GET', 'POST'])
@login_required
def new():
    require.app.create()
    form = AppForm(request.form)

    def respond(errors):
        return render_template('applications/new.html',
                               title=gettext("Create a Project"),
                               form=form, errors=errors)

    def _description_from_long_description():
        long_desc = form.long_description.data
        html_long_desc = misaka.render(long_desc)[:-1]
        remove_html_tags_regex = re.compile('<[^>]*>')
        blank_space_regex = re.compile('\n')
        text_desc = remove_html_tags_regex.sub("", html_long_desc)[:255]
        if len(text_desc) >= 252:
            text_desc = text_desc[:-3]
            text_desc += "..."
        return blank_space_regex.sub(" ", text_desc)

    if request.method != 'POST':
        return respond(False)

    if not form.validate():
        flash(gettext('Please correct the errors'), 'error')
        return respond(True)

    info = {}
    category_by_default = cached_cat.get_all()[0]

    app = App(name=form.name.data,
              short_name=form.short_name.data,
              description=_description_from_long_description(),
              long_description=form.long_description.data,
              owner_id=current_user.id,
              info=info,
              category_id=category_by_default.id)

    project_repo.save(app)

    msg_1 = gettext('Project created!')
    flash('<i class="icon-ok"></i> ' + msg_1, 'success')
    flash('<i class="icon-bullhorn"></i> ' +
          gettext('You can check the ') +
          '<strong><a href="https://docs.pybossa.com">' +
          gettext('Guide and Documentation') +
          '</a></strong> ' +
          gettext('for adding tasks, a thumbnail, using PyBossa.JS, etc.'),
          'info')
    auditlogger.add_log_entry(None, app, current_user)

    return redirect(url_for('.update', short_name=app.short_name))


@blueprint.route('/<short_name>/tasks/taskpresentereditor', methods=['GET', 'POST'])
@login_required
def task_presenter_editor(short_name):
    errors = False
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    title = app_title(app, "Task Presenter Editor")
    require.app.read(app)
    require.app.update(app)

    form = TaskPresenterForm(request.form)
    form.id.data = app.id
    if request.method == 'POST' and form.validate():
        db_app = project_repo.get(app.id)
        old_app = App(**db_app.dictize())
        old_info = dict(db_app.info)
        old_info['task_presenter'] = form.editor.data
        db_app.info = old_info
        auditlogger.add_log_entry(old_app, db_app, current_user)
        project_repo.update(db_app)
        cached_apps.delete_app(app.short_name)
        msg_1 = gettext('Task presenter added!')
        flash('<i class="icon-ok"></i> ' + msg_1, 'success')
        return redirect(url_for('.tasks', short_name=app.short_name))

    # It does not have a validation
    if request.method == 'POST' and not form.validate():  # pragma: no cover
        flash(gettext('Please correct the errors'), 'error')
        errors = True

    if app.info.get('task_presenter'):
        form.editor.data = app.info['task_presenter']
    else:
        if not request.args.get('template'):
            msg_1 = gettext('<strong>Note</strong> You will need to upload the'
                            ' tasks using the')
            msg_2 = gettext('CSV importer')
            msg_3 = gettext(' or download the project bundle and run the'
                            ' <strong>createTasks.py</strong> script in your'
                            ' computer')
            url = '<a href="%s"> %s</a>' % (url_for('app.import_task',
                                                    short_name=app.short_name), msg_2)
            msg = msg_1 + url + msg_3
            flash(msg, 'info')

            wrap = lambda i: "applications/presenters/%s.html" % i
            pres_tmpls = map(wrap, current_app.config.get('PRESENTERS'))

            app = add_custom_contrib_button_to(app, get_user_id_or_ip())
            return render_template(
                'applications/task_presenter_options.html',
                title=title,
                app=app,
                owner=owner,
                overall_progress=overall_progress,
                n_tasks=n_tasks,
                n_task_runs=n_task_runs,
                last_activity=last_activity,
                n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                n_volunteers=cached_apps.n_volunteers(app.get('id')),
                presenters=pres_tmpls)

        tmpl_uri = "applications/snippets/%s.html" \
            % request.args.get('template')
        tmpl = render_template(tmpl_uri, app=app)
        form.editor.data = tmpl
        msg = 'Your code will be <em>automagically</em> rendered in \
                      the <strong>preview section</strong>. Click in the \
                      preview button!'
        flash(gettext(msg), 'info')
    dict_app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('applications/task_presenter_editor.html',
                           title=title,
                           form=form,
                           app=dict_app,
                           owner=owner,
                           overall_progress=overall_progress,
                           n_tasks=n_tasks,
                           n_task_runs=n_task_runs,
                           last_activity=last_activity,
                           n_completed_tasks=cached_apps.n_completed_tasks(app.id),
                           n_volunteers=cached_apps.n_volunteers(app.id),
                           errors=errors)


@blueprint.route('/<short_name>/delete', methods=['GET', 'POST'])
@login_required
def delete(short_name):
    (app, owner, n_tasks,
    n_task_runs, overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, "Delete")
    require.app.read(app)
    require.app.delete(app)
    if request.method == 'GET':
        return render_template('/applications/delete.html',
                               title=title,
                               app=app,
                               owner=owner,
                               n_tasks=n_tasks,
                               overall_progress=overall_progress,
                               last_activity=last_activity)
    # Clean cache
    cached_apps.delete_app(app.short_name)
    cached_apps.clean(app.id)
    project_repo.delete(app)
    auditlogger.add_log_entry(app, None, current_user)
    flash(gettext('Project deleted!'), 'success')
    return redirect(url_for('account.profile', name=current_user.name))


@blueprint.route('/<short_name>/update', methods=['GET', 'POST'])
@login_required
def update(short_name):
    (app, owner, n_tasks,
     n_task_runs, overall_progress, last_activity) = app_by_shortname(short_name)

    def handle_valid_form(form):
        hidden = int(form.hidden.data)

        (app, owner, n_tasks, n_task_runs,
         overall_progress, last_activity) = app_by_shortname(short_name)

        new_project = project_repo.get_by_shortname(short_name)
        old_project = App(**new_project.dictize())
        old_info = dict(new_project.info)
        old_project.info = old_info
        if form.id.data == new_project.id:
            new_project.name=form.name.data
            new_project.short_name=form.short_name.data
            new_project.description=form.description.data
            new_project.long_description=form.long_description.data
            new_project.hidden=int(form.hidden.data)
            new_project.webhook=form.webhook.data
            new_project.info=app.info
            new_project.owner_id=app.owner_id
            new_project.allow_anonymous_contributors=form.allow_anonymous_contributors.data
            new_project.category_id=form.category_id.data

        new_project.set_password(form.password.data)
        project_repo.update(new_project)
        auditlogger.add_log_entry(old_project, new_project, current_user)
        cached_apps.delete_app(short_name)
        cached_apps.reset()
        cached_cat.reset()
        cached_apps.get_app(new_project.short_name)
        flash(gettext('Project updated!'), 'success')
        return redirect(url_for('.details',
                                short_name=new_project.short_name))

    require.app.read(app)
    require.app.update(app)

    title = app_title(app, "Update")
    if request.method == 'GET':
        form = AppUpdateForm(obj=app)
        upload_form = AvatarUploadForm()
        categories = project_repo.get_all_categories()
        form.category_id.choices = [(c.id, c.name) for c in categories]
        if app.category_id is None:
            app.category_id = categories[0].id
        form.populate_obj(app)

    if request.method == 'POST':
        upload_form = AvatarUploadForm()
        form = AppUpdateForm(request.form)
        categories = cached_cat.get_all()
        form.category_id.choices = [(c.id, c.name) for c in categories]

        if request.form.get('btn') != 'Upload':
            if form.validate():
                return handle_valid_form(form)
            flash(gettext('Please correct the errors'), 'error')
        else:
            if upload_form.validate_on_submit():
                app = project_repo.get(app.id)
                file = request.files['avatar']
                coordinates = (upload_form.x1.data, upload_form.y1.data,
                               upload_form.x2.data, upload_form.y2.data)
                prefix = time.time()
                file.filename = "app_%s_thumbnail_%i.png" % (app.id, prefix)
                container = "user_%s" % current_user.id
                uploader.upload_file(file,
                                     container=container,
                                     coordinates=coordinates)
                # Delete previous avatar from storage
                if app.info.get('thumbnail'):
                    uploader.delete_file(app.info['thumbnail'], container)
                app.info['thumbnail'] = file.filename
                app.info['container'] = container
                project_repo.save(app)
                cached_apps.delete_app(app.short_name)
                flash(gettext('Your project thumbnail has been updated! It may \
                                  take some minutes to refresh...'), 'success')
            else:
                flash(gettext('You must provide a file to change the avatar'),
                      'error')
            return redirect(url_for('.update', short_name=short_name))

    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('/applications/update.html',
                           form=form,
                           upload_form=upload_form,
                           app=app,
                           owner=owner,
                           n_tasks=n_tasks,
                           overall_progress=overall_progress,
                           n_task_runs=n_task_runs,
                           last_activity=last_activity,
                           n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                           n_volunteers=cached_apps.n_volunteers(app.get('id')),
                           title=title)


@blueprint.route('/<short_name>/')
def details(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    require.app.read(app)
    template = '/applications/app.html'

    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password

    title = app_title(app, None)
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    template_args = {"app": app, "title": title,
                     "owner": owner,
                     "n_tasks": n_tasks,
                     "overall_progress": overall_progress,
                     "last_activity": last_activity,
                     "n_completed_tasks": cached_apps.n_completed_tasks(app.get('id')),
                     "n_volunteers": cached_apps.n_volunteers(app.get('id'))}
    if current_app.config.get('CKAN_URL'):
        template_args['ckan_name'] = current_app.config.get('CKAN_NAME')
        template_args['ckan_url'] = current_app.config.get('CKAN_URL')
        template_args['ckan_pkg_name'] = short_name
    return render_template(template, **template_args)


@blueprint.route('/<short_name>/settings')
@login_required
def settings(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    title = app_title(app, "Settings")
    require.app.read(app)
    require.app.update(app)
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('/applications/settings.html',
                           app=app,
                           owner=owner,
                           n_tasks=n_tasks,
                           overall_progress=overall_progress,
                           n_task_runs=n_task_runs,
                           last_activity=last_activity,
                           n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                           n_volunteers=cached_apps.n_volunteers(app.get('id')),
                           title=title)


@blueprint.route('/<short_name>/tasks/import', methods=['GET', 'POST'])
@login_required
def import_task(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)
    title = app_title(app, "Import Tasks")
    loading_text = gettext("Importing tasks, this may take a while, wait...")
    dict_app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    template_args = dict(title=title, loading_text=loading_text,
                         app=dict_app,
                         owner=owner,
                         n_tasks=n_tasks,
                         overall_progress=overall_progress,
                         n_volunteers=n_volunteers,
                         n_completed_tasks=n_completed_tasks,
                         target='app.import_task')
    require.app.read(app)
    require.app.update(app)
    importer_type = request.form.get('form_name') or request.args.get('type')
    all_importers = importer.get_all_importer_names()
    if importer_type is not None and importer_type not in all_importers:
        raise abort(404)
    form = GenericBulkTaskImportForm()(importer_type, request.form)
    template_args['form'] = form

    if request.method == 'POST':
        if form.validate():  # pragma: no cover
            try:
                return _import_tasks(app, **form.get_import_data())
            except BulkImportException as err_msg:
                flash(err_msg, 'error')
            except Exception as inst:  # pragma: no cover
                current_app.logger.error(inst)
                msg = 'Oops! Looks like there was an error!'
                flash(gettext(msg), 'error')
        return render_template('/applications/importers/%s.html' % importer_type,
                                **template_args)

    if request.method == 'GET':
        template_tasks = current_app.config.get('TEMPLATE_TASKS')
        if importer_type is None:
            template_wrap = lambda i: "applications/tasks/gdocs-%s.html" % i
            task_tmpls = map(template_wrap, template_tasks)
            template_args['task_tmpls'] = task_tmpls
            importer_wrap = lambda i: "applications/tasks/%s.html" % i
            template_args['available_importers'] = map(importer_wrap, all_importers)
            return render_template('/applications/task_import_options.html',
                                   **template_args)
        if importer_type == 'flickr':
            template_args['albums'] = flickr.get_user_albums(session)
        if importer_type == 'dropbox':
            from pybossa.core import dropbox
            template_args['folders'] = dropbox.get_public_folders(session)
        if importer_type == 'gdocs' and request.args.get('template'):  # pragma: no cover
            template = request.args.get('template')
            form.googledocs_url.data = template_tasks.get(template)
        return render_template('/applications/importers/%s.html' % importer_type,
                                **template_args)


def _import_tasks(app, **form_data):
    number_of_tasks = importer.count_tasks_to_import(**form_data)
    if number_of_tasks <= MAX_NUM_SYNCHRONOUS_TASKS_IMPORT:
        msg = importer.create_tasks(task_repo, app.id, **form_data)
        flash(msg)
    else:
        importer_queue.enqueue(import_tasks, app.id, **form_data)
        flash(gettext("You're trying to import a large amount of tasks, so please be patient.\
            You will receive an email when the tasks are ready."))
    return redirect(url_for('.tasks', short_name=app.short_name))


@blueprint.route('/<short_name>/tasks/autoimporter', methods=['GET', 'POST'])
@login_required
def setup_autoimporter(short_name):
    if not current_user.pro and not current_user.admin:
        raise abort(403)
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)
    dict_app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    template_args = dict(app=dict_app,
                         owner=owner,
                         n_tasks=n_tasks,
                         overall_progress=overall_progress,
                         n_volunteers=n_volunteers,
                         n_completed_tasks=n_completed_tasks,
                         target='app.setup_autoimporter')
    require.app.read(app)
    require.app.update(app)
    importer_type = request.form.get('form_name') or request.args.get('type')
    all_importers = importer.get_all_importer_names()
    if importer_type is not None and importer_type not in all_importers:
        raise abort(404)
    form = GenericBulkTaskImportForm()(importer_type, request.form)
    template_args['form'] = form

    if app.has_autoimporter():
        current_autoimporter = app.get_autoimporter()
        importer_info = dict(**current_autoimporter)
        return render_template('/applications/task_autoimporter.html',
                                importer=importer_info, **template_args)

    if request.method == 'POST':
        if form.validate():  # pragma: no cover
            app.set_autoimporter(form.get_import_data())
            project_repo.save(app)
            auditlogger.log_event(app, current_user, 'create', 'autoimporter',
                                  'Nothing', json.dumps(app.get_autoimporter()))
            cached_apps.delete_app(short_name)
            flash(gettext("Success! Tasks will be imported daily."))
            return redirect(url_for('.setup_autoimporter', short_name=app.short_name))

    if request.method == 'GET':
        if importer_type is None:
            wrap = lambda i: "applications/tasks/%s.html" % i
            template_args['available_importers'] = map(wrap, all_importers)
            return render_template('applications/task_autoimport_options.html',
                                   **template_args)
        if importer_type == 'flickr':
            template_args['albums'] = flickr.get_user_albums(session)
    return render_template('/applications/importers/%s.html' % importer_type,
                                **template_args)


@blueprint.route('/<short_name>/tasks/autoimporter/delete', methods=['POST'])
@login_required
def delete_autoimporter(short_name):
    if not current_user.pro and not current_user.admin:
        raise abort(403)
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)
    dict_app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    template_args = dict(app=dict_app,
                         owner=owner,
                         n_tasks=n_tasks,
                         overall_progress=overall_progress,
                         n_volunteers=n_volunteers,
                         n_completed_tasks=n_completed_tasks)
    require.app.read(app)
    require.app.update(app)
    if app.has_autoimporter():
        autoimporter = app.get_autoimporter()
        app.delete_autoimporter()
        project_repo.save(app)
        auditlogger.log_event(app, current_user, 'delete', 'autoimporter',
                              json.dumps(autoimporter), 'Nothing')
        cached_apps.delete_app(short_name)
    return redirect(url_for('.tasks', short_name=app.short_name))


@blueprint.route('/<short_name>/password', methods=['GET', 'POST'])
def password_required(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    form = PasswordForm(request.form)
    if request.method == 'POST' and form.validate():
        password = request.form.get('password')
        cookie_exp = current_app.config.get('PASSWD_COOKIE_TIMEOUT')
        passwd_mngr = ProjectPasswdManager(CookieHandler(request, signer, cookie_exp))
        if passwd_mngr.validates(password, app):
            response = make_response(redirect(request.args.get('next')))
            return passwd_mngr.update_response(response, app, get_user_id_or_ip())
        flash(gettext('Sorry, incorrect password'))
    return render_template('applications/password.html',
                            app=app,
                            form=form,
                            short_name=short_name,
                            next=request.args.get('next'))


@blueprint.route('/<short_name>/task/<int:task_id>')
def task_presenter(short_name, task_id):
    (app, owner,n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    task = task_repo.get_task(id=task_id)
    if task is None:
        raise abort(404)
    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password

    if current_user.is_anonymous():
        if not app.allow_anonymous_contributors:
            msg = ("Oops! You have to sign in to participate in "
                   "<strong>%s</strong>"
                   "project" % app.name)
            flash(gettext(msg), 'warning')
            return redirect(url_for('account.signin',
                                    next=url_for('.presenter',
                                    short_name=app.short_name)))
        else:
            msg_1 = gettext(
                "Ooops! You are an anonymous user and will not "
                "get any credit"
                " for your contributions.")
            next_url = url_for('app.task_presenter',
                                short_name=short_name, task_id=task_id)
            url = url_for('account.signin', next=next_url)
            flash(msg_1 + "<a href=\"" + url + "\">Sign in now!</a>", "warning")

    title = app_title(app, "Contribute")
    template_args = {"app": app, "title": title, "owner": owner}

    def respond(tmpl):
        return render_template(tmpl, **template_args)

    if not (task.app_id == app.id):
        return respond('/applications/task/wrong.html')
    return respond('/applications/presenter.html')


@blueprint.route('/<short_name>/presenter')
@blueprint.route('/<short_name>/newtask')
def presenter(short_name):

    def invite_new_volunteers(app):
        user_id = None if current_user.is_anonymous() else current_user.id
        user_ip = request.remote_addr if current_user.is_anonymous() else None
        task = sched.new_task(app.id, app.info.get('sched'), user_id, user_ip, 0)
        return task is None and overall_progress < 100.0

    def respond(tmpl):
        if (current_user.is_anonymous()):
            msg_1 = gettext(msg)
            flash(msg_1, "warning")
        resp = make_response(render_template(tmpl, **template_args))
        return resp

    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, "Contribute")
    template_args = {"app": app, "title": title, "owner": owner,
                     "invite_new_volunteers": invite_new_volunteers(app)}
    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password

    if not app.allow_anonymous_contributors and current_user.is_anonymous():
        msg = "Oops! You have to sign in to participate in <strong>%s</strong> \
               project" % app.name
        flash(gettext(msg), 'warning')
        return redirect(url_for('account.signin',
                        next=url_for('.presenter', short_name=app.short_name)))

    msg = "Ooops! You are an anonymous user and will not \
           get any credit for your contributions. Sign in \
           now!"

    if app.info.get("tutorial") and \
            request.cookies.get(app.short_name + "tutorial") is None:
        resp = respond('/applications/tutorial.html')
        resp.set_cookie(app.short_name + 'tutorial', 'seen')
        return resp
    else:
        return respond('/applications/presenter.html')


@blueprint.route('/<short_name>/tutorial')
def tutorial(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, "Tutorial")

    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password
    return render_template('/applications/tutorial.html', title=title,
                           app=app, owner=owner)


@blueprint.route('/<short_name>/<int:task_id>/results.json')
def export(short_name, task_id):
    """Return a file with all the TaskRuns for a give Task"""
    # Check if the app exists
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password

    # Check if the task belongs to the app and exists
    task = task_repo.get_task_by(app_id=app.id, id=task_id)
    if task:
        taskruns = task_repo.filter_task_runs_by(task_id=task_id, app_id=app.id)
        results = [tr.dictize() for tr in taskruns]
        return Response(json.dumps(results), mimetype='application/json')
    else:
        return abort(404)


@blueprint.route('/<short_name>/tasks/')
def tasks(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, "Tasks")

    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())

    return render_template('/applications/tasks.html',
                           title=title,
                           app=app,
                           owner=owner,
                           n_tasks=n_tasks,
                           overall_progress=overall_progress,
                           last_activity=last_activity,
                           n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                           n_volunteers=cached_apps.n_volunteers(app.get('id')))


@blueprint.route('/<short_name>/tasks/browse', defaults={'page': 1})
@blueprint.route('/<short_name>/tasks/browse/<int:page>')
def tasks_browse(short_name, page):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, "Tasks")
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)

    def respond():
        per_page = 10
        offset = (page - 1) * per_page
        count = n_tasks
        app_tasks = cached_apps.browse_tasks(app.get('id'))
        page_tasks = app_tasks[offset:offset+per_page]
        if not page_tasks and page != 1:
            abort(404)

        pagination = Pagination(page, per_page, count)
        return render_template('/applications/tasks_browse.html',
                               app=app,
                               owner=owner,
                               tasks=page_tasks,
                               title=title,
                               pagination=pagination,
                               n_tasks=n_tasks,
                               overall_progress=overall_progress,
                               n_volunteers=n_volunteers,
                               n_completed_tasks=n_completed_tasks)
    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return respond()


@blueprint.route('/<short_name>/tasks/delete', methods=['GET', 'POST'])
@login_required
def delete_tasks(short_name):
    """Delete ALL the tasks for a given project"""
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    require.app.read(app)
    require.app.update(app)
    if request.method == 'GET':
        title = app_title(app, "Delete")
        n_volunteers = cached_apps.n_volunteers(app.id)
        n_completed_tasks = cached_apps.n_completed_tasks(app.id)
        app = add_custom_contrib_button_to(app, get_user_id_or_ip())
        return render_template('applications/tasks/delete.html',
                               app=app,
                               owner=owner,
                               n_tasks=n_tasks,
                               n_task_runs=n_task_runs,
                               n_volunteers=n_volunteers,
                               n_completed_tasks=n_completed_tasks,
                               overall_progress=overall_progress,
                               last_activity=last_activity,
                               title=title)
    else:
        tasks = task_repo.filter_tasks_by(app_id=app.id)
        task_repo.delete_all(tasks)
        msg = gettext("All the tasks and associated task runs have been deleted")
        flash(msg, 'success')
        cached_apps.delete_last_activity(app.id)
        cached_apps.delete_n_tasks(app.id)
        cached_apps.delete_n_task_runs(app.id)
        cached_apps.delete_overall_progress(app.id)
        return redirect(url_for('.tasks', short_name=app.short_name))


@blueprint.route('/<short_name>/tasks/export')
def export_to(short_name):
    """Export Tasks and TaskRuns in the given format"""
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)
    title = app_title(app, gettext("Export"))
    loading_text = gettext("Exporting data..., this may take a while")

    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password

    def respond():
        return render_template('/applications/export.html',
                               title=title,
                               loading_text=loading_text,
                               ckan_name=current_app.config.get('CKAN_NAME'),
                               app=app,
                               owner=owner,
                               n_tasks=n_tasks,
                               n_task_runs=n_task_runs,
                               n_volunteers=n_volunteers,
                               n_completed_tasks=n_completed_tasks,
                               overall_progress=overall_progress)


    def gen_json(table):
        n = getattr(task_repo, 'count_%ss_with' % table)(app_id=app.id)
        sep = ", "
        yield "["
        for i, tr in enumerate(getattr(task_repo, 'filter_%ss_by' % table)(app_id=app.id, yielded=True), 1):
            item = json.dumps(tr.dictize())
            if (i == n):
                sep = ""
            yield item + sep
        yield "]"

    def format_csv_properly(row, ty=None):
        tmp = row.keys()
        task_keys = []
        for k in tmp:
            k = "%s__%s" % (ty, k)
            task_keys.append(k)
        if (type(row['info']) == dict):
            task_info_keys = []
            tmp = row['info'].keys()
            for k in tmp:
                k = "%sinfo__%s" % (ty, k)
                task_info_keys.append(k)
        else:
            task_info_keys = []

        keys = sorted(task_keys + task_info_keys)
        values = []
        _prefix = "%sinfo" % ty
        for k in keys:
            prefix, k = k.split("__")
            if prefix == _prefix:
                if row['info'].get(k) is not None:
                    values.append(row['info'][k])
                else:
                    values.append(None)
            else:
                if row.get(k) is not None:
                    values.append(row[k])
                else:
                    values.append(None)

        return values

    def handle_task(writer, t):
        writer.writerow(format_csv_properly(t.dictize(), ty='task'))

    def handle_task_run(writer, t):
        writer.writerow(format_csv_properly(t.dictize(), ty='taskrun'))

    def get_csv(out, writer, table, handle_row):
        for tr in getattr(task_repo, 'filter_%ss_by' % table)(app_id=app.id,
                                                              yielded=True):
            handle_row(writer, tr)
        yield out.getvalue()

    def respond_json(ty):
        if ty not in ['task', 'task_run']:
            return abort(404)
        res = json_exporter.response_zip(app, ty)
        return res

    def create_ckan_datastore(ckan, table, package_id):
        new_resource = ckan.resource_create(name=table,
                                            package_id=package_id)
        ckan.datastore_create(name=table,
                              resource_id=new_resource['result']['id'])
        ckan.datastore_upsert(name=table,
                              records=gen_json(table),
                              resource_id=new_resource['result']['id'])

    def respond_ckan(ty):
        # First check if there is a package (dataset) in CKAN
        msg_1 = gettext("Data exported to ")
        msg = msg_1 + "%s ..." % current_app.config['CKAN_URL']
        ckan = Ckan(url=current_app.config['CKAN_URL'],
                    api_key=current_user.ckan_api)
        app_url = url_for('.details', short_name=app.short_name, _external=True)

        try:
            package, e = ckan.package_exists(name=app.short_name)
            if e:
                raise e
            if package:
                # Update the package
                owner = user_repo.get(app.owner_id)
                package = ckan.package_update(app=app, user=owner, url=app_url,
                                              resources=package['resources'])

                ckan.package = package
                resource_found = False
                for r in package['resources']:
                    if r['name'] == ty:
                        ckan.datastore_delete(name=ty, resource_id=r['id'])
                        ckan.datastore_create(name=ty, resource_id=r['id'])
                        ckan.datastore_upsert(name=ty,
                                              records=gen_json(ty),
                                              resource_id=r['id'])
                        resource_found = True
                        break
                if not resource_found:
                    create_ckan_datastore(ckan, ty, package['id'])
            else:
                owner = user_repo.get(app.owner_id)
                package = ckan.package_create(app=app, user=owner, url=app_url)
                create_ckan_datastore(ckan, ty, package['id'])
                #new_resource = ckan.resource_create(name=ty,
                #                                    package_id=package['id'])
                #ckan.datastore_create(name=ty,
                #                      resource_id=new_resource['result']['id'])
                #ckan.datastore_upsert(name=ty,
                #                     records=gen_json(ty),
                #                     resource_id=new_resource['result']['id'])
            flash(msg, 'success')
            return respond()
        except requests.exceptions.ConnectionError:
            msg = "CKAN server seems to be down, try again layer or contact the CKAN admins"
            current_app.logger.error(msg)
            flash(msg, 'danger')
        except Exception as inst:
            if len(inst.args) == 3:
                t, msg, status_code = inst.args
                msg = ("Error: %s with status code: %s" % (t, status_code))
            else: # pragma: no cover
                msg = ("Error: %s" % inst.args[0])
            current_app.logger.error(msg)
            flash(msg, 'danger')
        finally:
            return respond()

    def respond_csv(ty):
        # Export Task(/Runs) to CSV
        types = {
            "task": (
                Task, handle_task,
                (lambda x: True),
                gettext(
                    "Oops, the project does not have tasks to \
                    export, if you are the owner add some tasks")),
            "task_run": (
                model.task_run.TaskRun, handle_task_run,
                (lambda x: True),
                gettext(
                    "Oops, there are no Task Runs yet to export, invite \
                     some users to participate"))}
        try:
            table, handle_row, test, msg = types[ty]
        except KeyError:
            return abort(404)

        # TODO: change check for existence below
        t = getattr(task_repo, 'get_%s_by' % ty)(app_id=app.id)
        if t is not None:
            res = csv_exporter.response_zip(app, ty)
            return res
        else:
            flash(msg, 'info')
            return respond()

    export_formats = ["json", "csv"]
    if current_user.is_authenticated():
        if current_user.ckan_api:
            export_formats.append('ckan')

    ty = request.args.get('type')
    fmt = request.args.get('format')
    if not (fmt and ty):
        if len(request.args) >= 1:
            abort(404)
        app = add_custom_contrib_button_to(app, get_user_id_or_ip())
        return render_template('/applications/export.html',
                               title=title,
                               loading_text=loading_text,
                               ckan_name=current_app.config.get('CKAN_NAME'),
                               app=app,
                               owner=owner,
                               n_tasks=n_tasks,
                               n_task_runs=n_task_runs,
                               n_volunteers=n_volunteers,
                               n_completed_tasks=n_completed_tasks,
                               overall_progress=overall_progress)
    if fmt not in export_formats:
        abort(415)
    return {"json": respond_json, "csv": respond_csv, 'ckan': respond_ckan}[fmt](ty)


@blueprint.route('/<short_name>/stats')
def show_stats(short_name):
    """Returns App Stats"""
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)
    title = app_title(app, "Statistics")

    require.app.read(app)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password

    if not ((n_tasks > 0) and (n_task_runs > 0)):
        app = add_custom_contrib_button_to(app, get_user_id_or_ip())
        return render_template('/applications/non_stats.html',
                               title=title,
                               app=app,
                               owner=owner,
                               n_tasks=n_tasks,
                               overall_progress=overall_progress,
                               n_volunteers=n_volunteers,
                               n_completed_tasks=n_completed_tasks)

    dates_stats, hours_stats, users_stats = stats.get_stats(
        app.id,
        current_app.config['GEO'])
    anon_pct_taskruns = int((users_stats['n_anon'] * 100) /
                            (users_stats['n_anon'] + users_stats['n_auth']))
    userStats = dict(
        geo=current_app.config['GEO'],
        anonymous=dict(
            users=users_stats['n_anon'],
            taskruns=users_stats['n_anon'],
            pct_taskruns=anon_pct_taskruns,
            top5=users_stats['anon']['top5']),
        authenticated=dict(
            users=users_stats['n_auth'],
            taskruns=users_stats['n_auth'],
            pct_taskruns=100 - anon_pct_taskruns,
            top5=users_stats['auth']['top5']))

    tmp = dict(userStats=users_stats['users'],
               userAnonStats=users_stats['anon'],
               userAuthStats=users_stats['auth'],
               dayStats=dates_stats,
               hourStats=hours_stats)

    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('/applications/stats.html',
                           title=title,
                           appStats=json.dumps(tmp),
                           userStats=userStats,
                           app=app,
                           owner=owner,
                           n_tasks=n_tasks,
                           overall_progress=overall_progress,
                           n_volunteers=n_volunteers,
                           n_completed_tasks=n_completed_tasks)


@blueprint.route('/<short_name>/tasks/settings')
@login_required
def task_settings(short_name):
    """Settings page for tasks of the project"""
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    n_volunteers = cached_apps.n_volunteers(app.id)
    n_completed_tasks = cached_apps.n_completed_tasks(app.id)
    require.app.read(app)
    require.app.update(app)
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('applications/task_settings.html',
                           app=app,
                           owner=owner,
                           n_tasks=n_tasks,
                           overall_progress=overall_progress,
                           n_volunteers=n_volunteers,
                           n_completed_tasks=n_completed_tasks)


@blueprint.route('/<short_name>/tasks/redundancy', methods=['GET', 'POST'])
@login_required
def task_n_answers(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, gettext('Redundancy'))
    form = TaskRedundancyForm()
    require.app.read(app)
    require.app.update(app)
    if request.method == 'GET':
        return render_template('/applications/task_n_answers.html',
                               title=title,
                               form=form,
                               app=app,
                               owner=owner)
    elif request.method == 'POST' and form.validate():
        task_repo.update_tasks_redundancy(app, form.n_answers.data)
        # Log it
        auditlogger.log_event(app, current_user, 'update', 'task.n_answers',
                              'N/A', form.n_answers.data)
        msg = gettext('Redundancy of Tasks updated!')
        flash(msg, 'success')
        return redirect(url_for('.tasks', short_name=app.short_name))
    else:
        flash(gettext('Please correct the errors'), 'error')
        return render_template('/applications/task_n_answers.html',
                               title=title,
                               form=form,
                               app=app,
                               owner=owner)


@blueprint.route('/<short_name>/tasks/scheduler', methods=['GET', 'POST'])
@login_required
def task_scheduler(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, gettext('Task Scheduler'))
    form = TaskSchedulerForm()

    def respond():
        return render_template('/applications/task_scheduler.html',
                               title=title,
                               form=form,
                               app=app,
                               owner=owner)
    require.app.read(app)
    require.app.update(app)

    if request.method == 'GET':
        if app.info.get('sched'):
            for s in form.sched.choices:
                if app.info['sched'] == s[0]:
                    form.sched.data = s[0]
                    break
        return respond()

    if request.method == 'POST' and form.validate():
        app = project_repo.get_by_shortname(short_name=app.short_name)
        if app.info.get('sched'):
            old_sched = app.info['sched']
        else:
            old_sched = 'default'
        if form.sched.data:
            app.info['sched'] = form.sched.data
        project_repo.save(app)
        cached_apps.delete_app(app.short_name)
        # Log it
        if old_sched != app.info['sched']:
            auditlogger.log_event(app, current_user, 'update', 'sched',
                                  old_sched, app.info['sched'])
        msg = gettext("Project Task Scheduler updated!")
        flash(msg, 'success')

        return redirect(url_for('.tasks', short_name=app.short_name))
    else: # pragma: no cover
        flash(gettext('Please correct the errors'), 'error')
        return respond()


@blueprint.route('/<short_name>/tasks/priority', methods=['GET', 'POST'])
@login_required
def task_priority(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    title = app_title(app, gettext('Task Priority'))
    form = TaskPriorityForm()

    def respond():
        return render_template('/applications/task_priority.html',
                               title=title,
                               form=form,
                               app=app,
                               owner=owner)
    require.app.read(app)
    require.app.update(app)

    if request.method == 'GET':
        return respond()
    if request.method == 'POST' and form.validate():
        for task_id in form.task_ids.data.split(","):
            if task_id != '':
                t = task_repo.get_task_by(app_id=app.id, id=int(task_id))
                if t:
                    old_priority = t.priority_0
                    t.priority_0 = form.priority_0.data
                    task_repo.update(t)

                    if old_priority != t.priority_0:
                        old_value = json.dumps({'task_id': t.id,
                                                'task_priority_0': old_priority})
                        new_value = json.dumps({'task_id': t.id,
                                                'task_priority_0': t.priority_0})
                        auditlogger.log_event(app, current_user, 'update',
                                              'task.priority_0',
                                               old_value, new_value)
                else:  # pragma: no cover
                    flash(gettext(("Ooops, Task.id=%s does not belong to the app" % task_id)), 'danger')
        cached_apps.delete_app(app.short_name)
        flash(gettext("Task priority has been changed"), 'success')
        return respond()
    else:
        flash(gettext('Please correct the errors'), 'error')
        return respond()


@blueprint.route('/<short_name>/blog')
def show_blogposts(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    blogposts = blog_repo.filter_by(app_id=app.id)
    require.blogpost.read(app_id=app.id)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('applications/blog.html', app=app,
                           owner=owner, blogposts=blogposts,
                           overall_progress=overall_progress,
                           n_tasks=n_tasks,
                           n_task_runs=n_task_runs,
                           n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                           n_volunteers=cached_apps.n_volunteers(app.get('id')))


@blueprint.route('/<short_name>/<int:id>')
def show_blogpost(short_name, id):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)
    blogpost = blog_repo.get_by(id=id, app_id=app.id)
    if blogpost is None:
        raise abort(404)
    require.blogpost.read(blogpost)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('applications/blog_post.html',
                            app=app,
                            owner=owner,
                            blogpost=blogpost,
                            overall_progress=overall_progress,
                            n_tasks=n_tasks,
                            n_task_runs=n_task_runs,
                            n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                            n_volunteers=cached_apps.n_volunteers(app.get('id')))


@blueprint.route('/<short_name>/new-blogpost', methods=['GET', 'POST'])
@login_required
def new_blogpost(short_name):

    def respond():
        dict_app = add_custom_contrib_button_to(app, get_user_id_or_ip())
        return render_template('applications/new_blogpost.html',
                               title=gettext("Write a new post"),
                               form=form,
                               app=dict_app,
                               owner=owner,
                               overall_progress=overall_progress,
                               n_tasks=n_tasks,
                               n_task_runs=n_task_runs,
                               n_completed_tasks=cached_apps.n_completed_tasks(dict_app.get('id')),
                               n_volunteers=cached_apps.n_volunteers(dict_app.get('id')))


    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    form = BlogpostForm(request.form)
    del form.id

    if request.method != 'POST':
        require.blogpost.create(app_id=app.id)
        return respond()

    if not form.validate():
        flash(gettext('Please correct the errors'), 'error')
        return respond()

    blogpost = model.blogpost.Blogpost(title=form.title.data,
                                body=form.body.data,
                                user_id=current_user.id,
                                app_id=app.id)
    require.blogpost.create(blogpost)
    blog_repo.save(blogpost)
    cached_apps.delete_app(short_name)

    msg_1 = gettext('Blog post created!')
    flash('<i class="icon-ok"></i> ' + msg_1, 'success')

    return redirect(url_for('.show_blogposts', short_name=short_name))


@blueprint.route('/<short_name>/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update_blogpost(short_name, id):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    blogpost = blog_repo.get_by(id=id, app_id=app.id)
    if blogpost is None:
        raise abort(404)

    def respond():
        return render_template('applications/update_blogpost.html',
                               title=gettext("Edit a post"),
                               form=form, app=app, owner=owner,
                               blogpost=blogpost,
                               overall_progress=overall_progress,
                               n_task_runs=n_task_runs,
                               n_completed_tasks=cached_apps.n_completed_tasks(app.id),
                               n_volunteers=cached_apps.n_volunteers(app.id))

    form = BlogpostForm()

    if request.method != 'POST':
        require.blogpost.update(blogpost)
        form = BlogpostForm(obj=blogpost)
        return respond()

    if not form.validate():
        flash(gettext('Please correct the errors'), 'error')
        return respond()

    require.blogpost.update(blogpost)
    blogpost = model.blogpost.Blogpost(id=form.id.data,
                                title=form.title.data,
                                body=form.body.data,
                                user_id=current_user.id,
                                app_id=app.id)
    blog_repo.update(blogpost)
    cached_apps.delete_app(short_name)

    msg_1 = gettext('Blog post updated!')
    flash('<i class="icon-ok"></i> ' + msg_1, 'success')

    return redirect(url_for('.show_blogposts', short_name=short_name))


@blueprint.route('/<short_name>/<int:id>/delete', methods=['POST'])
@login_required
def delete_blogpost(short_name, id):
    app = app_by_shortname(short_name)[0]
    blogpost = blog_repo.get_by(id=id, app_id=app.id)
    if blogpost is None:
        raise abort(404)

    require.blogpost.delete(blogpost)
    blog_repo.delete(blogpost)
    cached_apps.delete_app(short_name)
    flash('<i class="icon-ok"></i> ' + 'Blog post deleted!', 'success')
    return redirect(url_for('.show_blogposts', short_name=short_name))


def _check_if_redirect_to_password(app):
    cookie_exp = current_app.config.get('PASSWD_COOKIE_TIMEOUT')
    passwd_mngr = ProjectPasswdManager(CookieHandler(request, signer, cookie_exp))
    if passwd_mngr.password_needed(app, get_user_id_or_ip()):
        return redirect(url_for('.password_required',
                                 short_name=app.short_name, next=request.path))


@blueprint.route('/<short_name>/auditlog')
@login_required
def auditlog(short_name):
    (app, owner, n_tasks, n_task_runs,
     overall_progress, last_activity) = app_by_shortname(short_name)

    logs = auditlogger.get_project_logs(app.id)
    require.auditlog.read(_app_id=app.id)
    redirect_to_password = _check_if_redirect_to_password(app)
    if redirect_to_password:
        return redirect_to_password
    app = add_custom_contrib_button_to(app, get_user_id_or_ip())
    return render_template('applications/auditlog.html', app=app,
                           owner=owner, logs=logs,
                           overall_progress=overall_progress,
                           n_tasks=n_tasks,
                           n_task_runs=n_task_runs,
                           n_completed_tasks=cached_apps.n_completed_tasks(app.get('id')),
                           n_volunteers=cached_apps.n_volunteers(app.get('id')))
