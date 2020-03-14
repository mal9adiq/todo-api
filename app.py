from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy


app = Flask(__name__)
app.config['SECRET_KEY'] = 'THIS IS MY SECRET KEY FOR DEBUGING ONLY USE SOME THING SECURE'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    email = db.Column(db.String(25))
    password = db.Column(db.String(80))
    todo_list = db.relationship('ToDo', backref='owner')


class ToDo (db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(20))
    desc = db.Column(db.String(20))
    status = db.Column(db.Integer)
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'))


@app.route('/login')
def login():
    return 'login'


@app.route('/sign_in')
def sign_in():
    return 'sign_in'


@app.route('/add_todo')
def add_todo():
    return 'add_todo'


@app.route('/update_todo')
def update_todo():
    return 'update_todo'


@app.route('/delete_todo')
def delete_todo():
    return 'delete_todo'


@app.route('/get_all_todo')
def get_all_todo():
    return 'get_all_todo'


if __name__ == '__main__':
    app.run(debug=True)
