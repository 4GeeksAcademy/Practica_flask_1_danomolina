"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
import datetime
from flask import Flask, request, jsonify, url_for
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
from werkzeug.security import generate_password_hash, check_password_hash
#from models import Person

app = Flask(__name__)
app.url_map.strict_slashes = False

db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')

MIGRATE = Migrate(app, db)
db.init_app(app)
jwt = JWTManager(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200

@app.route('/api/sign-up', methods=['POST'])
def sign_up():
    email = request.json.get('email')
    password = request.json.get('password')
    is_active = request.json.get('is_active')

    if not email:
        return jsonify({"error": "Email is required!"}), 400
    if not password:
        return jsonify({"error": "Password is required!"}), 400
    if not is_active:
        return jsonify({"error": "Is active is required!"}), 400
    
    #buscamos un usuario con ese email
    found = User.query.filter_by(email=email).first()
    if found:
        return jsonify ({ "error": "Email es already in use!"}), 400

    #Creamos un usuario con ese email si no existe ninguno
    user = User(email=email, password=generate_password_hash(password), is_active=is_active)
    user.save()

    if user:
        #ceando fecha de expiracion
        expires_at = datetime.timedelta(days=1)
        # creando el token al usuario
        access_token = create_access_token(identity=user.id, expires_delta=expires_at)
        
        #retornando la informacion del token junto a la informacion del usuario
        return jsonify({
            "status": "success",
            "messege": "User registered succesfully",     
            "access_token": access_token,
            "currentUser": user.serialize()
        }), 200 
    
    return jsonify({"error": "please, try again later!"}), 400


@app.route('/api/sign-in', methods=['POST'])
def sign_in():
    email = request.json.get('email')
    password = request.json.get('password')
    
    if not email:
        return jsonify({"error": "Email is required!"}), 400
    if not password:
        return jsonify({"error": "Password is required!"}), 400
    
    # Buscamos si existe el usuario y este activo
    user = User.query.filter_by(email=email, is_active=True).first()
    # si no consigo el usuario indico que tiene un error
    if not user:
        return jsonify({"error": "Incorrect Credentials!"}),401
    
    # Valido si la password que me esta entregando  es igual a la que esta en la base de dato
    if not check_password_hash(user.password, password):
        return jsonify({"error": "Incorrect Credentials!"}),401
    
    if user:
        # creando fecha de expiración
        expires_at = datetime.timedelta(days=1)
        # creando el token al usuario
        access_token = create_access_token(identity=user.id, expires_delta=expires_at)
        
        # rwtornando la información del token a la información del usuario
        return jsonify({
            "status": "success",
            "messege": "User logged succesfully",     
            "access_token": access_token,
            "currentUser": user.serialize()
        }), 200 

    return jsonify({"error": "please, try again later!"}), 400

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def profile(): 
    id = get_jwt_identity() # accedemos al usuario que esta solicitando la información
    user = User.query.get(id)

    if not user:
        return jsonify({"user": "User is invalid!"}), 401

    return jsonify(user.serialize()), 200




# this only runs if `$ python src/app.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)