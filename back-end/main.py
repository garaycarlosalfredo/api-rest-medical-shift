from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_marshmallow import Marshmallow
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
#Clase 68 - 101 pyhton 
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret-key-goes-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:@localhost:3306/medical-shift2'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Order matters: Initialize SQLAlchemy before Marshmallow
ma = Marshmallow(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


##TABLE DATABASE
class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.DateTime)
    appointment_date = db.Column(db.DateTime)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    patient_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    activity_1 = db.Column(db.String(100), db.ForeignKey('activity.id'))

class Activity(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    qantity = db.Column(db.Integer)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    rol_id = db.Column(db.String(100), db.ForeignKey('rol.id'))
    rol = db.relationship("Rol", backref="users")

    def __init__(self,email,password,name,rol_id):
        self.email = email
        self.password = password
        self.name = name
        self.rol_id = rol_id


class Rol(db.Model):
    id = db.Column(db.String(100), primary_key=True)
    rol = db.Column(db.String(100), unique=True)

##MARSHMALLOW SCHEMA 
class UserSchema(ma.SQLAlchemySchema):
    class Meta:
        fields = ('id', 'email', 'password', 'name','rol_id')

class UserBasicSchema(ma.SQLAlchemySchema):
    class Meta:
        fields = ('id', 'email', 'name','rol_id')

class RolSchema(ma.SQLAlchemySchema):
    class Meta: 
        fields = ('id','rol')

class ActivitySchema(ma.SQLAlchemySchema):
    class Meta:
        field = ('id','qantity')

class AppointmentSchema(ma.SQLAlchemySchema):
    class Meta:
        fields = ('id','date','appointment_date','doctor_id','patient_id','activity_1','activity_2','activity_3','activity_4')

db.create_all()

#marswmallow instances
user_schema = UserSchema()
users_schema = UserSchema(many=True)

userbasic_schema = UserBasicSchema()
usersbasic_schema = UserBasicSchema(many=True)

rol_schema = RolSchema()
rols_schema = RolSchema(many=True)

activity_schema = ActivitySchema()
activities_schema = ActivitySchema(many=True)

appointment_schema = AppointmentSchema()
appointment_schema = AppointmentSchema(many = True)

##SOLO PARA PRUEBAS################################################
@app.route('/master_users', methods=["GET"])
def get_usuarios():
    usuarios = User.query.all()
    result = users_schema.dump(usuarios)
    return jsonify(result)

@app.route('/users', methods=["GET"])
def get_usuariosbasico():
    usuarios = User.query.all()
    result = usersbasic_schema.dump(usuarios)
    return jsonify(result)

@app.route('/rols', methods=["GET"])
def get_roles():
    roles = Rol.query.all()
    result = rols_schema.dump(roles)
    return jsonify(result)

#POST
@app.route('/adduser',methods=['POST'])
def insert_user():
    email = request.json['email']
    password = request.json['password']
    name = request.json['name']
    rol_id = request.json['rol_id']


    nuevo_usuario = User(email, password,name,rol_id)

    db.session.add(nuevo_usuario)
    db.session.commit()
    return user_schema.jsonify(nuevo_usuario)

##SOLO PARA PRUEBAS################################################

@app.route('/')
def home():
    # Every render_template has a logged_in variable set.
    #return render_template("index.html", logged_in=current_user.is_authenticated)
    return "API-REST"

@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            #User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=request.form.get('email'),
            name=request.form.get('name'),
            password=hash_and_salted_password,
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')
    
        user = User.query.filter_by(email=email).first()
        #Email doesn't exist or password incorrect.
        if not user:
            flash("That email does not exist, please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Password incorrect, please try again.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('secrets'))

    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


if __name__ == "__main__":
    app.run(debug=True)