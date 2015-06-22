#!flask/bin/python

import os, json, logging
from datetime import datetime
from flask import Flask, abort, request, jsonify, g
from flask.ext.sqlalchemy import SQLAlchemy
from flask.ext.httpauth import HTTPBasicAuth
from passlib.apps import custom_app_context as pwd_context
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

# initialization
app = Flask(__name__)
app.config['SECRET_KEY'] = 'ini ceritaku, mana ceritamu'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True
app.config['SERVER_NAME'] = '127.0.0.1:5000'

# logger initialization
file_handler = logging.FileHandler('app.log')
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)

# extensions
db = SQLAlchemy(app)
auth = HTTPBasicAuth()

# create users table
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    password_hash = db.Column(db.String(64))
    tweets = db.relationship("Tweet", backref="user")

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)
    
    def serialize(self):
        return {
            'id': self.id,
            'username': self.username
        }

    # generating a new token
    def generate_auth_token(self, expiration = 3600): # expire in 3600 secs
        s = Serializer(app.config['SECRET_KEY'], expires_in = expiration)
        return s.dumps({ 'id': self.id })

    # authentication with token
    @staticmethod
    def verify_auth_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
            # just to make sure what is inside data
            # app.logger.info('The data inside token :' + str(data['id']))
        except SignatureExpired:
            # this line below is not necessary et al
            # comment this line to avoid error: local variable 'data' referenced before assignment
            # Sess.query.filter_by(user_id=data['id']).first().logged_in = False
            db.session.commit()
            app.logger.info('TOKEN :: Token expired.')
            return None # valid token, but expired
        # logout stuck in here. dunno why
        except BadSignature:
            # comment this line to avoid error: local variable 'data' referenced before assignment
            # Sess.query.filter_by(user_id=data['id']).first().logged_in = False
            db.session.commit()
            app.logger.info('TOKEN :: Invalid token.')
            return None # invalid token
        if not Sess.query.filter_by(user_id=data['id']).first().logged_in:
            app.logger.info('TOKEN :: Not login yet')
            return None 
        user = User.query.get(data['id'])
        return user

# create tweets table
class Tweet(db.Model):
    __tablename__ = 'tweets'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    tweet = db.Column(db.String(150))
    time = db.Column(db.DateTime(timezone=False))

    def serialize(self):
        return {
            'id': self.id,
            'tweet': self.tweet,
            'time': self.time.isoformat()
        }

# create tokens table
class Sess(db.Model):
    __tablename__ = 'tokens'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    logged_in = db.Column(db.Boolean)

# custom callback to log in
@auth.verify_password
def verify_password(username, password):
    # first try to authenticate by token
    token = request.headers.get('X-CSRF-Token')
    app.logger.info('Getting token..')
    if token is None:
        # try to authenticate with username
        app.logger.info('No token found. Auth with username and password.')
        user = User.query.filter_by(username=username).first()
        if not user or not user.verify_password(password):
            app.logger.info('User not found. Bad username and password combination.')
            return False
    else:
        app.logger.info('Token found. Verify auth token.')
        user = User.verify_auth_token(token)
        if user is None:
            app.logger.info('Something wrong with the token.')
            return False
    g.user = user
    app.logger.info('It works like a charm. You have an access.')
    return True

# register a new user
@app.route('/api/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        abort(400)    # missing arguments
    if User.query.filter_by(username=username).first() is not None:
        return jsonify(status=21,taken=username), 400    # existing user
    user = User(username=username)
    user.hash_password(password)
    db.session.add(user)
    db.session.commit()
    ss = Sess(user_id=user.id,logged_in=False)
    db.session.add(ss)
    db.session.commit()
    return jsonify(username=user.username), 201

# get all users
@app.route('/api/users', methods=['GET'])
def get_users():
    users = User.query.all()
    if users is None:
        abort(400)
    us = []
    for u in users:
        us.append(u.serialize())
    return jsonify(users=us)

# get a spesific user
@app.route('/api/users/<int:id>', methods=['GET'])
def get_user(id):
    user = User.query.get(id)
    if not user:
        abort(400)
    return jsonify(user=user.username)

# login
@app.route('/api/login', methods=['POST'])
@auth.login_required
def post_login():
    token = g.user.generate_auth_token(3600) # login for 3600 seconds
    Sess.query.filter_by(user_id=g.user.id).first().logged_in = True
    db.session.commit()
    return jsonify(token=token.decode('ascii'),duration=3600)

# logout
@app.route('/api/logout', methods=['POST'])
@auth.login_required
def post_logout():
    Sess.query.filter_by(user_id=g.user.id).first().logged_in = False
    db.session.commit()
    app.logger.info('Token removed. You are logged out.')
    return jsonify(status=86)

# search
@app.route('/api/tweet/search', methods=['GET'])
def get_search():
    query = request.args.get('q')
    # return query
    tweets = Tweet.query.filter(Tweet.tweet.like("%"+query+"%")).all()
    tw = []
    for t in tweets:
        tw.append(t.serialize())
    return jsonify(tweets=tw)

# get all tweets
@app.route('/api/tweet', methods=['GET'])
def get_tweets():
    tweets = Tweet.query.all()
    tw = []
    for t in tweets:
        tw.append(t.serialize())
    return jsonify(tweets=tw)

# get a spesific tweet
@app.route('/api/tweet/<int:id>', methods=['GET'])
def get_tweet(id):
    tweet = Tweet.query.get(id)
    if tweet is None:
        abort(404)    # tweet not found
    tweet = tweet.serialize()
    return jsonify(tweet=tweet)

# post a new tweet
@app.route('/api/tweet', methods=['POST'])
@auth.login_required
def post_tweet():    
    tweet = request.json.get('tweet')
    time = datetime.now()
    if tweet is None:
        abort(400)    # missing arguments
    tw = Tweet(user_id=g.user.id,tweet=tweet,time=time)
    db.session.add(tw)
    db.session.commit()
    tw = tw.serialize()
    return jsonify(tweet=tw), 201

# edit an existing tweet
@app.route('/api/tweet/<int:id>', methods=['PATCH'])
@auth.login_required
def patch_tweet(id):
    tweet = request.json.get('tweet')
    if tweet is None:
        abort(400)    # missing arguments
    if Tweet.query.filter_by(id=id).first() is None:
        abort(400)    # no tweet found
    tw = Tweet.query.filter_by(id=id).first()
    if tw.user_id != g.user.id:
        abort(400)    # tweet not owned
    tw.tweet = tweet
    tw.time = datetime.now()
    db.session.commit()
    tw = tw.serialize()
    return jsonify(tweet=tw)

# delete a tweet
@app.route('/api/tweet/<int:id>', methods=['DELETE'])
@auth.login_required
def delete_tweet(id):
    if Tweet.query.filter_by(id=id).first() is None:
        abort(400)    # no tweet found
    tw = Tweet.query.filter_by(id=id).first()
    if tw.user_id != g.user.id:
        abort(400)    # tweet not owned
    tweet = tw.tweet
    db.session.delete(tw)
    db.session.commit()
    return jsonify(status=86)

# start the magic
if __name__ == '__main__':
    if not os.path.exists('db.sqlite'):
        db.create_all()
    app.run(debug=True)
