# import os
# import secrets
# from werkzeug.utils import secure_filename
import tomllib
from flask import Flask, redirect, request, flash, render_template, url_for, send_from_directory
from werkzeug.exceptions import RequestEntityTooLarge
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey, Integer, String, Boolean, Uuid
from sqlalchemy.orm import Mapped, mapped_column, DeclarativeBase, relationship
from flask_bcrypt import Bcrypt
import uuid
from typing import List
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user, current_user

with open("config.toml", "rb") as f:
    config = tomllib.load(f)

def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in config["allowed_extensions"]


app = Flask(__name__)
app.config["SECRET_KEY"] = config["secret_key"]
app.config['UPLOAD_FOLDER'] = config["upload_folder"]
app.config["SQLALCHEMY_DATABASE_URI"] = config["sqlalchemy_database_uri"]
app.config['MAX_CONTENT_LENGTH'] = config["max_content_length"]

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
db.init_app(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.login_message_category = "info"
login_manager.init_app(app)



class User(UserMixin, db.Model):
    __tablename__ = 'user'
    # uuid: Mapped[Uuid] = mapped_column(Uuid, primary_key=True)
    id: Mapped[str] = mapped_column(String(16), primary_key=True, unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    bio: Mapped[str] = mapped_column(String(256))
    #! Warning: relationship 'Constellation.owner' will copy column user.name to column constellation.owner_name,
    #! which conflicts with relationship(s): 'User.owned_constellations' (copies user.name to constellation.owner_name).
    #! https://sqlalche.me/e/20/qzyx
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    owned_constellations: Mapped[List["Constellation"]] = relationship()
    sent_messages: Mapped[List['Message']] = relationship()


class Constellation(db.Model):
    __tablename__ = 'constellation'
    name: Mapped[str] = mapped_column(String(16), primary_key=True, unique=True, nullable=False)
    description: Mapped[str] = mapped_column(String(256))
    is_private: Mapped[bool] = mapped_column(Boolean, nullable=False)
    owner_name: Mapped[str] = mapped_column(ForeignKey("user.id"))
    owner: Mapped["User"] = relationship("User", backref="constellation")
    belonging_messages: Mapped[List['Message']] = relationship()
    belonging_invites: Mapped[List['Invite']] = relationship()
    members: Mapped[List['Invite']] = relationship()

class Message(db.Model):
    __tablename__ = 'message'
    uuid: Mapped[Uuid] = mapped_column(Uuid, primary_key=True)
    author_name: Mapped[str] = mapped_column(ForeignKey("user.id"))
    author: Mapped['User'] = relationship('User', backref='message')
    content: Mapped[str] = mapped_column(String(4096))
    constellation_name: Mapped[str] = mapped_column(ForeignKey('constellation.name'))
    constellation: Mapped['Constellation'] = relationship('Constellation', backref='message')

class Invite(db.Model):
    __tablename__ = 'invite'
    uuid: Mapped[Uuid] = mapped_column(Uuid, primary_key=True)
    constellation_name: Mapped[str] = mapped_column(ForeignKey('constellation.name'))
    constellation: Mapped['Constellation'] = relationship('Constellation', backref='invite')

class Member(db.Model):
    __tablename__= 'member'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_name: Mapped[str] = mapped_column(ForeignKey("user.id"))
    user: Mapped["User"] = relationship("User", backref="member")
    constellation_name: Mapped[str] = mapped_column(ForeignKey('constellation.name'))
    constellation: Mapped['Constellation'] = relationship('Constellation', backref='member')
    is_moderator: Mapped[bool] = mapped_column(Boolean)

with app.app_context():
    db.create_all()
    # db.drop_all()
    print("DB is up and running")

@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form.get("email")).first() 
        if user:
            flash("Such email already exists!", category="warning")
            return redirect(url_for('signup'))

        user = User(
            id=request.form["username"],
            email=request.form["email"],
            password_hash=bcrypt.generate_password_hash(request.form["password"]).decode('utf-8'),
            bio="Placeholder bio"
        )
        db.session.add(user)
        db.session.commit()

        flash("Account successfully created!", category="success")
        return redirect(url_for('index'))

    return render_template("register.html")


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True

        user = User.query.filter_by(email=email).first()
        if not user or not bcrypt.check_password_hash(user.password_hash, password):
            flash("Incorrect login details. Please try again.", category="danger")

        login_user(user, remember=remember)
        flash(f"Logged in as @{user.id}", category='info')
        return redirect(url_for('user', name=user.id))
    return render_template("login.html")

@app.route('/create', methods=["GET", "POST"])
@login_required
def create():
    if request.method == "POST":
        constellation_name = request.form.get("constellation_name")

        user = current_user
        constellation = Constellation(
            name=constellation_name,
            description=request.form.get("description"),
            is_private=False,
            owner=user
        )
        invite = Invite(
            uuid=uuid.uuid4(),
            constellation=constellation
        )
        member = Member(
            user=current_user,
            constellation=constellation,
            is_moderator=True
        )
        db.session.add(constellation)
        db.session.add(invite)
        db.session.add(member)
        db.session.commit()
        flash(f'Constellation "{constellation_name}" was successfully created!', category="success")
        # return redirect(url_for("constellation", name=constellation_name))
        return redirect(url_for('constellation', name=constellation_name))

    return render_template("create.html")


# @app.route('/posts')
# def posts():
#     return render_template("fragments/posts.html", cards=example_cards)

@app.route('/*/<string:name>', methods=["GET", "POST"])
@login_required
def constellation(name):
    if len(db.session.query(Member).filter_by(constellation_name=name, user_name=current_user.id).all()) == 0:
        flash("You are not invited!", category="warning")
        return redirect(url_for('index'))
    if request.method == "POST":
        constellation = db.get_or_404(Constellation, name)
        message_content = request.form.get("message_content")
        
        user = current_user

        message = Message(
            uuid=uuid.uuid4(),
            content=message_content,
            author=user,
            constellation=constellation
        )
        db.session.add(message)
        db.session.commit()
        #! file uploads are currently disabled
        # check if the post request has the file part
        # if 'file' in request.files:
        #     file = request.files['file']
        #     if file and file.filename != '':
        #         if allowed_file(secure_filename(file.filename)):
        #             filename = secrets.token_urlsafe(8) + '.' + secure_filename(file.filename).rsplit('.', 1)[1].lower()
        #             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        #             print(url_for('download_file', name=filename))
        #         else:
        #             flash("This file type is not allowed.", category="warning")
        #             return render_template("constellation.html", name=constellation_id)

        flash("Message successfully posted!", category="success")
        return redirect(url_for('constellation', name=name))
    
    constellation = db.get_or_404(Constellation, name)
    return render_template("constellation/view.html", constellation=constellation)

@app.route('/*/<string:name>/edit', methods=['GET', 'POST'])
@login_required
def edit_constellation(name):
    constellation = db.get_or_404(Constellation, name)
    if current_user.id != constellation.owner_name:
        return "Unauthorized", 401
    if request.method == 'POST':
        db.session.query(Constellation).filter_by(name=name).update({Constellation.description: request.form.get("description")})
        db.session.commit()
        flash('Constellation successfully edited!', category='success')
        return redirect(url_for('constellation', name=name))
    
    return render_template("constellation/edit.html", constellation=constellation)

@app.route('/*/<string:name>/leave')
@login_required
def leave_constellation(name):
    constellation = db.get_or_404(Constellation, name)
    if len(db.session.query(Member).filter_by(constellation_name=name, user_name=current_user.id).all()) == 0:
        flash("You are not invited!", category="warning")
        return redirect(url_for('index'))
    
    db.session.query(Member).filter_by(constellation_name=name, user_name=current_user.id).delete()
    db.session.commit()
    flash("Left the constellation.", category="info")
    return redirect(url_for('index'))


@app.route('/constellation/<string:name>/delete')
@login_required
def delete_constellation(name):
    constellation = db.get_or_404(Constellation, name)
    if current_user.id != constellation.owner_name:
        return "Unauthorized", 401
    db.session.query(Message).filter_by(constellation_name=name).delete()
    db.session.query(Invite).filter_by(constellation_name=name).delete()
    db.session.query(Member).filter_by(constellation_name=name).delete()
    db.session.query(Constellation).filter_by(name=name).delete()
    db.session.commit()
    flash('Constellation successfully deleted!', category='success')
    return redirect(url_for('index'))

@app.route('/msg/<uuid:uuid>')
@login_required
def message(uuid):
    message = db.get_or_404(Message, uuid)
    if len(db.session.query(Member).filter_by(constellation_name=message.constellation_name, user_name=current_user.id).all()) == 0:
        flash("You are not invited!", category="warning")
        return redirect(url_for('index'))
    return render_template("message/view.html", message=message)

@app.route('/msg/<uuid:uuid>/delete')
@login_required
def delete_message(uuid):
    message = db.get_or_404(Message, uuid)
    if current_user.id != message.author_name or current_user.id != message.constellation.owner_name:
        return "Unauthorized", 401
    db.session.query(Message).filter_by(uuid=uuid).delete()
    db.session.commit()
    flash('Message successfully deleted!', category='success')
    return redirect(url_for('constellation', name=message.constellation_name))

@app.route('/msg/<uuid:uuid>/edit', methods=['GET', 'POST'])
@login_required
def edit_message(uuid):
    message = db.get_or_404(Message, uuid)
    if current_user.id != message.author_name:
        return "Unauthorized", 401
    if request.method == 'POST':
        print(current_user.id)
        print(message.author_name)
        
        message_content = request.form.get("message_content")
        db.session.query(Message).filter_by(uuid=uuid).update({Message.content: message_content})
        db.session.commit()

        flash('Message successfully edited!', category='success')
        return redirect(url_for('constellation', name=message.constellation_name))
    
    return render_template('message/edit.html', message=message)

#! file uploads are currently disabled
# @app.route('/user-media/<string:name>')
# def download_file(name):
#     return send_from_directory(app.config["UPLOAD_FOLDER"], name)

@app.route('/@/<string:name>')
@login_required
def user(name):
    user = db.get_or_404(User, name)
    return render_template("user/view.html", user=user)

@app.route('/user/edit', methods=['GET', 'POST'])
@login_required
def edit_user():
    user = current_user
    if request.method == 'POST':
        bio = request.form.get("bio")
        #email = request.form.get("email")

        db.session.query(User).filter_by(id=user.id).update({User.bio: bio})
        db.session.commit()

        flash('User successfully edited!', category='success')
        return redirect(url_for('user', name=user.id))
    
    return render_template("user/edit.html", user=user)

@app.route('/user/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out.", category="info")
    return redirect(url_for('index'))

@app.route('/user/edit/password', methods=['GET', 'POST'])
@login_required
def edit_password():
    # user = db.session.get(User, current_user)
    return "Password change is not available yet."

@app.route('/user/delete')
@login_required
def delete_user():
    user = current_user
    logout_user()
    db.session.query(Message).filter_by(author_name=user.id).delete()
    db.session.query(User).filter_by(id=user.id).delete()
    db.session.query(Constellation).filter_by(owner_name=user.id).delete()
    db.session.commit()
    flash('User successfully deleted!', category='success')
    return redirect(url_for('index'))

@app.route('/*')
@login_required
def constellation_list():
    constellation_list = db.session.query(Constellation).filter_by(is_private=False).all()
    return render_template("constellation/list.html", constellation_list=constellation_list)

@app.route('/invite/<uuid:uuid>')
@login_required
def invite(uuid):
    invite = db.get_or_404(Invite, uuid)
    if len(db.session.query(Member).filter_by(constellation_name=invite.constellation_name, user_name=current_user.id).all()) > 0:
        return redirect(url_for('constellation', name=invite.constellation_name))
    return render_template("invite.html", invite=invite)

@app.route('/invite/<uuid:uuid>/join')
@login_required
def invite_join(uuid):
    invite = db.get_or_404(Invite, uuid)
    if len(db.session.query(Member).filter_by(constellation_name=invite.constellation_name, user_name=current_user.id).all()) > 0:
        return redirect(url_for('constellation', name=invite.constellation_name))
    member = Member(
        user = current_user,
        constellation = invite.constellation,
        is_moderator=False
    )
    db.session.add(member)
    db.session.commit()
    flash(f"Joined to *{invite.constellation_name}!", category='success')
    return redirect(url_for("constellation", name=invite.constellation_name))

# Error handling

@app.errorhandler(RequestEntityTooLarge)
def request_entity_too_large(error):
    flash("Request entity too large (413). This error probably means the file you've uploaded is bigger than 2 MB.",
          category="danger")
    return redirect(request.url)

# @login_manager.unauthorized_handler
# def unauthorized_handler():
#     return 'Unauthorized', 401

@app.errorhandler(404)
def page_not_found(error):
    return render_template("404.html"), 404
