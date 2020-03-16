from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from functools import wraps
import jwt
import datetime
from flask_babel import Babel, gettext


app = Flask(__name__)
app.config['SECRET_KEY'] = 'THIS IS MY SECRET KEY FOR DEBUGING ONLY USE SOME THING SECURE'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todos.db'
app.config['BABEL_DEFAULT_LOCALE'] = 'en'

db = SQLAlchemy(app)
babel = Babel(app)


@babel.localeselector
def get_locale():

    language = request.headers
    if language:
        return request.headers['language']
    else:
        return 'en'


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


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'msg': gettext('Login is required'), 'statusCode': 400})

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(
                public_id=data['public_id']).first()
        except:
            return jsonify({'msg': gettext('Login is required'), 'statusCode': 400})
        return f(current_user, *args, **kwargs)
    return decorated


@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return jsonify({'statusCode:': 400, "msg": gettext("Email or password is incorrect")})
    # TODO: email validation
    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return jsonify({'statusCode:': 400, "msg": gettext("Email or password is incorrect")})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id': user.public_id, 'exp': datetime.datetime.utcnow(
        ) + datetime.timedelta(days=30)}, app.config['SECRET_KEY'])

        return jsonify({'statusCode': 200, 'token': token.decode('UTF-8')})
    return jsonify({'statusCode:': 400, "msg": gettext("Email or password is incorrect")})


@app.route('/sign_up', methods=['POST'])
def sign_up():
    data = request.get_json()

    if not data or not data['password'] or not data['email']:
        return jsonify({'statusCode:': 400, "msg": gettext("Email or password is incorrect")})

    hashed_password = generate_password_hash(
        data['password'], method='sha256')
    new_user = User(public_id=str(uuid.uuid4()),
                    email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'statusCode': 200, 'msg': 'User Has Been Created Successfully'})


@app.route('/add_todo', methods=['POST'])
@token_required
def add_todo(current_user):
    data = request.get_json()

    new_todo = ToDo(title=data['title'], desc=data['desc'],
                    status=data['status'], owner_id=current_user.id)
    db.session.add(new_todo)
    db.session.commit()
    todo = {'id': new_todo.id, 'status': new_todo.status,
            'title': new_todo.title, 'desc': new_todo.desc}
    return jsonify({'statusCode': 200, 'msg': 'ToDo Has Been Created Successfully', 'todo': todo})


@app.route('/update_todo/<id>', methods=['PUT'])
@token_required
def update_todo(current_user, id):
    data = request.get_json()

    new_todo = ToDo.query.filter_by(id=id, owner_id=current_user.id).first()
    new_todo.status = data['status']
    db.session.commit()
    todo = {'id': new_todo.id, 'status': new_todo.status,
            'title': new_todo.title, 'desc': new_todo.desc}
    return jsonify({'statusCode': 200, 'msg': 'ToDo Has Been Updated Successfully', 'todo': todo})

    return 'update_todo'


@app.route('/delete_todo/<id>')
@token_required
def delete_todo(current_user, id):
    todo = ToDo.query.with_parent(current_user).filter_by(id=id).first()

    if not todo:
        return jsonify({'statusCode': 400, "msg": gettext('There no todo to delete')})

    db.session.delete(todo)
    db.session.commit()

    return jsonify({"statusCode": 200, "msg": gettext('Todo has been deleted successfully')})


@app.route('/get_all_todo')
@token_required
def get_all_todo(current_user):

    todos_list = current_user.todo_list

    todos = []

    for todo in todos_list:
        todo_obj = {'id': todo.id, "title": todo.title,
                    "desc": todo.desc, 'status': todo.status}

        todos.append(todo_obj)

    return jsonify({'statusCode': 200, 'todos': todos})


if __name__ == '__main__':
    app.run(debug=True)
