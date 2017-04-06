import datetime
import urllib3

from flask import Flask, request, session, flash, \
    render_template, redirect, url_for, Markup
from functools import wraps
from markdown import markdown
from markdown.extensions.codehilite import CodeHiliteExtension
from markdown.extensions.extra import ExtraExtension
from micawber import bootstrap_basic, parse_html
from micawber.cache import Cache as OEmbedCache
from playhouse.flask_utils import FlaskDB, get_object_or_404, object_list
from playhouse.sqlite_ext import *
from hashlib import md5

# blog configuration values

# you may consider using a one-way hash to generate the password, and then
# use the hash again in the login view to perform the comparison. This is just
# simplicity.
ADMIN_PASSWORD = md5(('diasijas').encode('utf-8')).hexdigest()
APP_DIR = os.path.dirname(os.path.realpath(__file__))

# the playhouse.flask_utils.FlaskDB accepts database URL configuration
DATABASE = 'sqliteext:///%s' % os.path.join(APP_DIR, 'blog.db')
DEBUG = False

# the secret key is used internally by Flask to encrypt session data stored
# in cookies. Make this unique for your app
SECRET_KEY = os.urandom(24)  # used by FLask to encrypt session cookie.

# this is used by micawber, which will attempt to generate rich media
# embedded objects with maxwidth=800
SITE_WIDTH = 800


# create a Flask WSGI app and configure it using values from the module
app = Flask(__name__)
app.config.from_object(__name__)


# FlaskDB is a wrapper for a peewee database that sets us pre/post-request
# hooks for managing database connections
flask_db = FlaskDB(app)

# the 'database' is the actual peewee database, as opposed to flask_db
# which is the wrapper
database = flask_db.database

# configure micawber with the default OEmbed providers (YouTube, Flickr, etc)
# we'll use a simple in-memory cache so that multiple requests fir the same
# video don't require multiple network requests.
oembed_providers = bootstrap_basic(OEmbedCache())


class Entry(flask_db.Model):
    title = CharField()
    slug = CharField(unique=True)
    content = TextField()
    published = BooleanField(index=True)
    timestamp = DateTimeField(default=datetime.datetime.now(), index=True)

    @property
    def html_content(self):
        """
        Generate HTML representation of the markdown-formatted blog entry,
        and also convert any media URLs into rich media objects such as video
        players or images.
        :return:
        """
        hilite = CodeHiliteExtension(linenums=False, css_class='highlight')
        extras = ExtraExtension()
        markdown_content = markdown(self.content, extensions=[hilite, extras])
        oembed_content = parse_html(
            markdown_content,
            oembed_providers,
            urlize_all=True,
            maxwidth=app.config['SITE_WIDTH']
        )
        return Markup(oembed_content)  # we trust the HTML content, so it will not be escaped when rendered

    def save(self, *args, **kwargs):
        # generate a URL-friendly representation of the entry's title
        if not self.slug:
            self.slug = re.sub('[^\w]+', '-', self.title.lower())
        ret = super(Entry, self).save(*args, **kwargs)
        # store search content
        self.update_search_index()
        return ret

    def update_search_index(self):
        # create a row in the FTSEntry table with the post content. This will
        # allow us to use SQLite's awesome full-text search extension to
        # search our entries
        try:
            fts_entry = FTSEntry.get(FTSEntry.entry_id == self.id)
        except FTSEntry.DoesNotExist:
            fts_entry = FTSEntry(entry_id=self.id)
            force_insert = True
        else:
            force_insert = False
        fts_entry.content = '\n'.join((self.title, self.content))
        fts_entry.save(force_insert=force_insert)

    @classmethod
    def public(cls):
        return Entry.select().where(Entry.published == True)

    @classmethod
    def search(cls, query):
        words = [word.strip() for word in query.split() if word.strip()]
        if not words:
            # return empty set
            return Entry.select().where(Entry.id == 0)
        else:
            search = ' '.join(words)

        # query the full-text search index for entries matching the given
        # search query, then join the actual Entry data on the matching
        # search result.
        return (FTSEntry.select(
            FTSEntry,
            Entry,
            FTSEntry.rank().alias('score')
        ).join(Entry, on=(FTSEntry.entry_id == Entry.id).alias('entry')).where(
            (Entry.published == True) &
            (FTSEntry.match(search))
        ).order_by(SQL('score').desc()))

    @classmethod
    def drafts(cls):
        return Entry.select().where(Entry.published == False)


class FTSEntry(FTSModel):
    entry_id = IntegerField(unique=True)
    content = TextField()

    class Meta:
        database = database


class User(flask_db.Model):
    username = CharField(unique=True)
    password = CharField()
    email = CharField()
    join_date = DateTimeField()

    class Meta:
        database = database

    def gravatar_url(self, size=40):
        return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
               (md5(self.email.strip().lower().encode('utf-8')).hexdigest(), size)


class Comment(flask_db.Model):
    content = TextField()

    class Meta:
        database = database


def authenticate_user(user):
    session['logged_in'] = True
    session['user_id'] = user.id
    session['username'] = user.username
    flash('You are logged in as %s' % user.username)


def get_current_user():
    if session.get('logged_in'):
        return User.get(User.id == session['user_id'])


# login_required function
def login_required(f):
    @wraps(f)
    def inner(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login', next=request.path))
        return f(*args, **kwargs)

    return inner


@app.route('/login/', methods=['GET', 'POST'])
def login():
    # next_url = request.args.get('next') or request.form['next']
    if request.method == 'POST':
        if md5((request.form['password']).encode('utf-8')).hexdigest() == app.config['ADMIN_PASSWORD']:
            session['logged_in'] = True
            session.permanent = True  # use cookie to store session
            flash('You are now logged in.', 'success')
            return redirect(url_for('blog'))
        else:
            flash('Incorrect password.', 'danger')
    return render_template('login.html')


@app.route('/us_login/', methods=['GET', 'POST'])
def us_login():
    if request.method == 'POST':
        if request.form['username'] and request.form['password']:
            session['logged_in'] = True
            session.permanent = False
            flash('You are now logged in.', 'success')
            return redirect(url_for('comments'))
        else:
            if not request.form['username']:
                flash('Incorrect username', 'danger')
            if not request.form['password']:
                flash('Incorrect password', 'danger')
    return render_template('us_login.html')


@app.route('/logout/', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        # session.clear()
        session.pop('logged_in', None)
        flash('You were logged out.', 'danger')
    return render_template('logout.html')


# implementing views
@app.route('/blog/')
def blog():
    search_query = request.args.get('q')
    if search_query:
        query = Entry.search(search_query)
    else:
        query = Entry.public().order_by(Entry.timestamp.desc())

    # the 'object_list' helper will take a base query and then handle
    # paginating the results if there are more than 20. for more info see
    # the docs:
    # http://docs.peewee-orm.com/en/latest/peewee/playhouse.html#object_list
    return object_list('blog.html', query, search=search_query, check_bounds=True)


@app.route('/drafts/')
@login_required
def drafts():
    query = Entry.drafts().order_by(Entry.timestamp.desc())
    return object_list('blog.html', query, check_bounds=False)


# the create view should be placed immediately before the detail view.
# because if we didn't put it before detail, then Flask would interpret
# requests to /create/ as attempting to request the detail page for an
# entry with the slug create, which we don't want.
@app.route('/create/', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'POST':
        if request.form['title'] and request.form['content']:
            entry = Entry.create(
                title=request.form['title'],
                content=request.form['content'],
                published=request.form['published'] or False
            )
            try:
                with database.atomic():
                    entry.save()
            except IntegrityError:
                flash('Error: this title is already in use.', 'danger')
            flash('Entry created successfully.', 'success')
            if entry.published:
                return redirect(url_for('detail', slug=entry.slug))
            else:
                return redirect(url_for('edit', slug=entry.slug))
        else:
            flash('Title and Content are required.', 'danger')
    return render_template('create.html')


@app.route('/<slug>/')
def detail(slug):
    if session.get('logged_in'):
        query = Entry.select()
    else:
        query = Entry.public()
    entry = get_object_or_404(query, Entry.slug == slug)
    # redirect(url_for('edit'))
    return render_template('detail.html', entry=entry)


# the edit view is similar and can be placed after the detail view.
# The only difference is that we will call get_object_or_404 to
# verify that the entry exists:
@app.route('/<slug>/edit/', methods=['GET', 'POST'])
@login_required
def edit(slug):
    entry = get_object_or_404(Entry, Entry.slug == slug)
    if request.method == 'POST':
        if request.form['title'] and request.form['content']:
            try:
                entry.title = request.form['title']
                entry.content = request.form['content']
                entry.published = request.form['published'] or False
                entry.save()
                flash('Entry saved successfully.', 'success')
                if entry.published:
                    return redirect(url_for('detail', slug=entry.slug))
                else:
                    return redirect(url_for('edit', slug=entry.slug))
            except Entry.DoesNotExist:
                flash('Title and Content are required.', 'danger')
    return render_template('edit.html', entry=entry)


@app.route('/<slug>/join/', methods=['GET', 'POST'])
def join(slug):
    entry = get_object_or_404(Entry, Entry.slug == slug)
    if request.method == 'POST':
        if request.form['username'] and request.form['password']:
            try:
                with database.atomic():
                    user = User.create(
                        username=request.form['username'],
                        password=md5((request.form['password']).encode('utf-8')).hexdigest(),
                        email=request.form['email'],
                        join_date=datetime.datetime.now()
                    )
                authenticate_user(user)
                return redirect(url_for('blog'))

            except IntegrityError:
                flash('That username is already used.', 'danger')
    return render_template('join.html', entry=entry)


@app.route('/contact/', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST' and request.form['name']:
        if request.form['email'] and request.form['content']:
            flash('Thank you for you message', 'success')
            return redirect(url_for('blog'))
        else:
            flash('Email and Content are required')
    return render_template('contact.html')


@app.route('/comments/')
def comments():
    det = detail(slug=Entry.slug)
    if request.method == 'POST':
        if request.form['content']:
            try:
                with database.atomic():
                    comment = Comment.create(
                        content=request.form['content']
                    )
            except Comment.DoesNotExist:
                flash('Your comment is empty', 'danger')
        return det


@app.route('/', methods=['GET', 'POST'])
def about():
    search_query = request.args.get('q')
    if search_query:
        query = Entry.search(search_query)
    else:
        query = Entry.public().order_by(Entry.timestamp.desc())
    return object_list('about.html', query, search=search_query, check_bounds=True)


# template filter
@app.template_filter('clean_querystring')
def clean_querystring(request_args, *keys_to_remove, **new_values):
    querystring = [dict((key, value)) for key, value in request_args.items()]
    for key in keys_to_remove:
        querystring.pop(key, None)
    querystring.update(new_values)
    return urllib3.urlencode(querystring)


# initialization code
def main():
    database.create_tables([Entry, FTSEntry, User, Comment], safe=True)
    app.run(debug=True)


if __name__ == '__main__':
    main()
