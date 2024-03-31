from flask import Flask, render_template, url_for, request, redirect, flash, session
# from data import Articles
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from wtforms import Form, StringField, PasswordField, TextAreaField, validators
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
app.secret_key = "secret123"
app.app_context().push()

# Articles = Articles()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50))
    username = db.Column(db.String(25))
    password = db.Column(db.String(60))
    register_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"User('{self.username}', '{self.email}', '{self.password}')"

class Article(db.Model):
    __tablename__ = 'article'  # Explicitly specify the table name
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    body = db.Column(db.Text)
    author = db.Column(db.String(255))
    create_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"Article('{self.title}', '{self.author}', '{self.create_date}')"


class RegisterForm(Form):
    name = StringField("Name", [validators.Length(min=6, max=50)])
    username = StringField("Username", [validators.Length(min=4, max=25)])
    email = StringField("Email", [validators.Length(min=6, max=50)])
    password = StringField("Password", [
        validators.DataRequired(),
        validators.EqualTo('confirm', message="Passwords do not match.")
    ])
    confirm = PasswordField("Confirm Password")

class LoginForm(Form):
    username = StringField("Username", [validators.Length(min=4, max=25)])
    password = PasswordField("Password", [validators.DataRequired()])

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash("Unauthorized, Please login", "danger")
            return redirect(url_for("login"))
    return wrap

@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/articles')
@is_logged_in  # Ensure user is logged in
def articles():
    # Check if 'username' is present in the session
    if 'username' in session:
        # Retrieve articles authored by the logged-in user
        articles = Article.query.filter_by(author=session['username']).all()
        if len(articles) > 0:  # Check if articles list is not empty
            return render_template('articles.html', articles=articles)
        else:
            msg = "No Articles Found"
            return render_template('articles.html', msg=msg)
    else:
        # If 'username' is not present in the session, redirect to login page
        flash('Unauthorized. Please login.', 'danger')
        return redirect(url_for('login'))


@app.route('/article/<int:id>')
def article(id):
    article = Article.query.get(id)
    return render_template('article.html', article=article)

@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm(request.form)
    if request.method == "POST" and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        new_user = User(name=name, email=email, username=username, password=password)

        db.session.add(new_user)
        db.session.commit()

        flash('You are now registered and can log in', 'success')

        return redirect(url_for("login"))
    return render_template('register.html', form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm(request.form)
    if request.method == "POST" and form.validate():
        username = form.username.data
        password_candidate = form.password.data

        user = User.query.filter_by(username=username).first()

        if user:
            if sha256_crypt.verify(password_candidate, user.password):
                session['logged_in'] = True
                session['username'] = username

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error, form=form)
        else:
            error = 'Username not found'
            return render_template('login.html', error=error, form=form)

    return render_template('login.html', form=form)

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash("You are now logged out", "success")
    return redirect(url_for("login"))

@app.route('/dashboard')
@is_logged_in
def dashboard():
    articles = Article.query.filter_by(author=session['username']).all()
    if len(articles) > 0:  # Check if articles list is not empty
        return render_template('dashboard.html', articles=articles)
    else:
        msg = "No Articles Found"
        return render_template('dashboard.html', msg=msg)


class ArticleForm(Form):
    title = StringField("Title", [validators.Length(min=1, max=200)])
    body = TextAreaField("Body", [validators.Length(min=30)])

@app.route('/add_article', methods=["GET", "POST"])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == "POST" and form.validate():
        title = form.title.data
        body = form.body.data
        author = session['username']

        new_article = Article(title=title, body=body, author=author)

        db.session.add(new_article)
        db.session.commit()

        flash('Article created successfully', 'success')
        return redirect(url_for("dashboard"))

    return render_template('add_article.html', form=form)

@app.route('/edit_article/<int:id>', methods=["GET", "POST"])
@is_logged_in
def edit_article(id):
    article = Article.query.get_or_404(id)  # Retrieve the article by its ID or return a 404 error if not found
    form = ArticleForm(request.form, obj=article)  # Populate the form with the article data

    if request.method == "POST" and form.validate():
        # Update the article with the form data
        article.title = form.title.data
        article.body = form.body.data

        # No need to update author and create_date, as they remain the same

        db.session.commit()  # Commit the changes to the database

        flash('Article updated successfully', 'success')
        return redirect(url_for("dashboard"))

    return render_template('edit_article.html', form=form)

@app.route('/delete_article/<int:id>', methods=["GET", "POST"])
@is_logged_in
def delete_article(id):
    article = Article.query.get_or_404(id)  # Retrieve the article by its ID or return a 404 error if not found

    if request.method == "POST":
        db.session.delete(article)  # Delete the article from the database
        db.session.commit()  # Commit the changes to the database

        flash('Article deleted successfully', 'success')
        return redirect(url_for("dashboard"))

    return render_template('delete_article.html', article=article)


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
