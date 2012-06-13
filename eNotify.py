# -*- coding: utf-8 -*-
"""
    eNotify is a butchered version of the Flask MiniTwit example application.
    The main modifications being to implement functionality for gntp push
    notifications of messages, and implement external post mechanisms for use
    by scripts and external applciations.  If the language will allow you to do
    an http post, you should be able to post notifications to eNotify.

    External post sample code :
    Bash :
        curl -d "username=rpm_builds&message=An externally posted message." http://10.97.154.41:5000/add_insecure_message

    python :
        from urllib import urlencode
        from urllib2 import urlopen, Request
        params = {  'username' : 'rpm_builds',
                    'message' : 'An externally posted message.'}
        data = urlencode(params)
        req = Request('http://10.97.154.41:5000/add_insecure_message', data)
        response = urlopen(req)
        print "Post response : %s " % response.read()

    <ORIGINAL DOCUMENTATION>
        MiniTwit
        ~~~~~~~~

        A microblogging application written with Flask and sqlite3.

        :copyright: (c) 2010 by Armin Ronacher.
        :license: BSD, see LICENSE for more details.
    </ORIGINAL DOCUMENTATION>
"""
from __future__ import with_statement
import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from time import time
import logging
from logging.handlers import RotatingFileHandler
from contextlib import closing

from flask import Flask, request, session, url_for, redirect, render_template, abort, g, flash, jsonify

from werkzeug import check_password_hash, generate_password_hash

from wtforms import Form, IntegerField, HiddenField, TextField, PasswordField, validators

import gntp.notifier


# configuration
DATABASE = 'eNotify.db'
PER_PAGE = 30
DEBUG = True
SECRET_KEY = 'onceUponATimeThereWasATigerCalledTrevor'
LOGGING_PATH = "eNotify.log"


# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)

class RegistrationForm(Form):
    hostname = TextField('hostname', [validators.Length(min=1, max=60)])
    port = IntegerField('port', default=23053 )
    password = PasswordField('Growl Password', [
        validators.Required(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    client_id = HiddenField('client_id')
    confirm = PasswordField('Repeat Growl Password')

def connect_db():
    """Returns a new connection to the database."""
    return sqlite3.connect(app.config['DATABASE'])


def init_db():
    """Creates the database tables."""
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = g.db.execute('select user_id from user where username = ?',
                       [username]).fetchone()
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)

@app.before_request
def before_request():
    """Make sure we are connected to the database each request and look
    up the current user so that we know he's there.
    """
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


@app.teardown_request
def teardown_request(exception):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/')
def timeline():
    """Shows a users timeline or if no user is logged in it will
    redirect to the public timeline.  This timeline shows the user's
    messages as well as all the messages of followed users.
    """
    if not g.user:
        return redirect(url_for('public_timeline'))
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id and (
            user.user_id = ? or
            user.user_id in (select whom_id from follower
                                    where who_id = ?))
        order by message.pub_date desc limit ?''',
        [session['user_id'], session['user_id'], PER_PAGE]))

@app.route('/notify_subscribers')
def notify_subscribers():
    unnotified_messages = query_db('select message_id from message where notified != 1')

    for message in unnotified_messages:
        # Iterate through our unnotified messages.
        message_id = message['message_id']
        # Find the user that posted the message.
        message = query_db('select author_id, text from message where message_id = ?',[int(message_id)], one=True)
        author_id = message['author_id']
        message_text = message['text']
        username = query_db('select username from user where user_id = ?',[int(author_id)], one=True)['username']

        # print "Author is : %s" % author_id
        # Find the followers of that user, and their default sticky status.
        follower_list = query_db('select who_id, default_to_sticky from follower where whom_id = ?',[int(author_id)])
        # print "Followers : %s" % follower_list

        for follower in follower_list:
            # Get their registered notification clients.
            clients_list = query_db('select hostname, port, password from registered_clients where user_id = ?',[int(follower['who_id'])])
            print "Clients List : %s" % clients_list
            for client in clients_list:
                print "Client : %s" % client
                try:
                    growl = gntp.notifier.GrowlNotifier(
                        applicationName = "eNotify",
                        notifications = ["New Updates","New Messages"],
                        defaultNotifications = ["New Messages"],
                        hostname = str(client['hostname']),
                        password = str(client['password']),
                        port = int(client['port'])
                    )
                    # growl.register()
                    growl.notify(
                        noteType = "New Messages",
                        title = "Message from %s" % username,
                        description = "%s" % message_text,
                        icon = "http://example.com/icon.png",
                        sticky = follower['default_to_sticky'],
                        priority = 1,
                    )

                except:
                    app.logger.exception("Failed to send notification to user : %d" % int(follower['who_id']))
        # set the message as notified.
        g.db.execute('update message set notified=? where message_id=?',
        [True, message_id])
        g.db.commit()
    return redirect(url_for('public_timeline'))

@app.route('/public')
def public_timeline():
    """Displays the latest messages of all users."""
    return render_template('timeline.html', messages=query_db('''
        select message.*, user.* from message, user
        where message.author_id = user.user_id
        order by message.pub_date desc limit ?''', [PER_PAGE]))


@app.route('/<username>')
def user_timeline(username):
    """Display's a users tweets."""
    profile_user = query_db('select * from user where username = ?',
                            [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        followed = query_db('''select 1 from follower where
            follower.who_id = ? and follower.whom_id = ?''',
            [session['user_id'], profile_user['user_id']],
            one=True) is not None
    return render_template('timeline.html', messages=query_db('''
            select message.*, user.* from message, user where
            user.user_id = message.author_id and user.user_id = ?
            order by message.pub_date desc limit ?''',
            [profile_user['user_id'], PER_PAGE]), followed=followed,
            profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    """Adds the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    g.db.execute('insert into follower (who_id, whom_id, default_to_sticky) values (?, ?, ?)',
                [session['user_id'], whom_id, False])
    g.db.commit()
    flash('You are now following "%s"' % username,'success')
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    """Removes the current user as follower of the given user."""
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    g.db.execute('delete from follower where who_id=? and whom_id=?',
                [session['user_id'], whom_id])
    g.db.commit()
    flash('You are no longer following "%s"' % username,'success')
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_insecure_message', methods=['POST'])
def add_insecure_message():
    # These work slightly differently as externally facing, and accept username or user_id's
    username = request.values.get('username', "", type=str)
    user_id = request.values.get('user_id', 0, type=int)
    message_text = request.values.get('message', "", type=str)

    for value in request.values:
        app.logger.debug("got %s : %s" % (value , request.values[value]))

    if username == "" and user_id == 0 or message_text == "":
        app.logger.debug("Got Params Username : %s , user_id : %s, message : %s" % (username, user_id, message_text))
        abort(401)
    else:
        if user_id == 0:
        # get user_id from username
            user_id = query_db('select user_id from user where username = ?',[username], one=True)['user_id']
        # might be using the insecure posting mechanism, checking the user is enabled for it.
        if query_db('select insecure from user where user_id = ?',[user_id], one=True)['insecure'] == True:
            # Account is enabled for insecure posts.
            response = g.db.execute('''insert into message (author_id, text, pub_date)
                values (?, ?, ?)''', (user_id, message_text,int(time())))
            g.db.commit()
            #message_id = response.lastrowid
            notify_subscribers()
            return "Success"
    return "Failed"


@app.route('/add_message', methods=['POST'])
def add_message():
    """Registers a new message for the user."""
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        response = g.db.execute('''insert into message (author_id, text, pub_date)
            values (?, ?, ?)''', (session['user_id'], request.form['text'],
            int(time())))

        g.db.commit()
        #message_id = response.lastrowid
        flash('Your message was posted','success')
        # Now using a delayed url call.
        notify_subscribers()
    return redirect(url_for('timeline'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    app.logger.debug("Hitting profile.")
    if g.user:
        form = RegistrationForm(request.form)
        if request.method == 'POST' and form.validate():
            # Ascertain if its an update or a new client.
            if form.client_id.data != "":
                # Looks like its an update
                app.logger.info("Update required, client_id : %s" % form.client_id.data)
            else:
                # Looks like its a new item.
                g.db.execute('''insert into registered_clients (user_id, hostname, port, password, date_added, date_modified)
                    values (?, ?, ?, ?, ?, ?)''', (int(session['user_id']), form.hostname.data, form.port.data, form.password.data, format_datetime(time()), format_datetime(time())))
                g.db.commit()
                #newId = g.db.lastrowid
                try:
                    growl = gntp.notifier.GrowlNotifier(
                        applicationName = "eNotify",
                        notifications = ["New Updates","New Messages"],
                        defaultNotifications = ["New Messages"],
                        hostname = form.hostname.data,
                        password = form.password.data,
                        port= int(form.port.data)
                    )
                    growl.register()
                    growl.notify(
                        noteType = "New Messages",
                        title = "Hello %s" % g.user['username'],
                        description = "Thankyou for registering.",
                        #icon = "http://example.com/icon.png",
                        sticky = True,
                        priority = 1,
                    )
                    flash('Client registered sucessfully','success')
                except:
                    flash("Failed to push notification to client.  Please check your firewall settings.",'error')
                    app.logger.exception("Failed to send test notification")

        registered_clients=query_db('''
            select client_id, hostname, port, password, date_added, date_modified from registered_clients
            where user_id = ?''', [int(session['user_id'])])
        following_list=query_db('''
            select whom_id from follower
            where who_id = ?''', [int(session['user_id'])])

        followed_users=[]
        app.logger.debug("Followed list : %s" % following_list)
        for follow in following_list:
            app.logger.debug("Follow : %s" % follow)
            followed_user=query_db('''
                select user_id, username from user
                where user_id=?''', [follow['whom_id']], one=True)
            followed_users.append({'user_id': followed_user['user_id'], 'username': followed_user['username'],})

        app.logger.debug("Followed Users : %s" % followed_users)

        return render_template('profile.html', registered_clients=registered_clients,followed_users=followed_users, form=form)
    else:
        return redirect(url_for('login'))

@app.route('/unregister_client/<int:client_id>', methods=['GET'])
def unregister_client(client_id):
    # Check the client_id is owned by the currrent users session.
    client_record=query_db('''
        select user_id from registered_clients
        where client_id = ?''', [int(client_id)])
    app.logger.debug("Client Record : %s" % client_record)
    if int(session['user_id']) == client_record[0]['user_id']:
        g.db.execute('''delete from registered_clients where user_id=? and client_id=?''', (int(session['user_id']), int(client_id)))
        g.db.commit()
        flash("Sucessfully removed client.",'success')
        return redirect(url_for('profile'))
    else:
        flash("Failed to remove client, client not registered to this user.",'error')
        return redirect(url_for('profile'))

@app.route('/toggle_insecure', methods=['GET'])
def toggle_insecure():
    if g.user:
        app.logger.debug("insecure state is : %s" % g.user['insecure'])
        if g.user['insecure'] == True:
            try:
                g.db.execute('''update user set insecure=? where user_id=?''', (False, int(session['user_id'])))
                g.db.commit()
                flash("Sucessfully disabled insecure posting.",'success')
            except:
                flash("Failed to toggle insecure flag.",'error')
        else:
            try:
                g.db.execute('''update user set insecure=? where user_id=?''', (True, int(session['user_id'])))
                g.db.commit()
                flash("Sucessfully enabled insecure posting.",'success')
            except:
                flash("Failed to toggle insecure flag.",'error')
                        
    return redirect(url_for('profile'))

@app.route('/test_client/<int:client_id>', methods=['GET'])
def test_client(client_id):
    # Check the client_id is owned by the currrent users session.
    client_record=query_db('''
        select user_id, hostname, port, password from registered_clients
        where client_id = ?''', [int(client_id)], one=True)
    app.logger.debug("client test requested for : %d" % client_id)

    try:
        growl = gntp.notifier.GrowlNotifier(
            applicationName = "eNotify",
            notifications = ["New Updates","New Messages"],
            defaultNotifications = ["New Messages"],
            hostname = client_record['hostname'],
            password = client_record['password'],
            port = client_record['port']
        )
        growl.register()
        growl.notify(
            noteType = "New Messages",
            title = "Test Message",
            description = "You Requested a test message",
            icon = "http://example.com/icon.png",
            sticky = True,
            priority = 1,
        )
        flash("Sucessfully tested client.",'success')
    except:
        flash("Failed to push notification to client.  Please check your firewall settings.",'error')
        app.logger.exception("Failed to send test notification")

    return redirect(url_for('profile'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            g.db.execute('''insert into user (
                username, email, pw_hash) values (?, ?, ?)''',
                [request.form['username'], request.form['email'],
                 generate_password_hash(request.form['password'])])
            g.db.commit()
            flash('You were successfully registered and can login now','success')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url


if __name__ == '__main__':
    ADMINS = ['chris@fane.cc']
    if not app.debug:
        mail_handler = SMTPHandler('127.0.0.1',
                                   'server@fane.cc',
                                   ADMINS, 'YourApplication Failed')
        mail_handler.setLevel(logging.ERROR)
        app.logger.addHandler(mail_handler)

    # create console handler and set level to debug, with auto log rotate max size 10mb keeping 10 logs.
    file_handler = RotatingFileHandler( LOGGING_PATH , maxBytes=10240000, backupCount=10)

    # create formatter
    log_formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(name)s - %(message)s")
    # add formatter to our console handler
    file_handler.setFormatter(log_formatter)

    # example code for various logging levels
    #logger.debug("debug message")
    #logger.info("info message")
    #logger.warn("warn message")
    #logger.error("error message")
    #logger.critical("critical message")
    #logger.exception("exception message followed by trace")

    file_handler.setLevel(logging.DEBUG)
    app.logger.addHandler(file_handler)

    app.run(host='0.0.0.0',port=8081)
