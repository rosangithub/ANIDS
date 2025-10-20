from flask import Flask, request,render_template, redirect,session
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import joblib
import numpy as np
import sklearn


app = Flask(__name__)

#load the model
model = joblib.load('model/StackingEnsemble.joblib')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
db = SQLAlchemy(app)
app.secret_key = 'secret_key'


# List of features in the exact order
FEATURES = [
    'fwd_packet_length_max',
    'fwd_packet_length_mean',
    'bwd_packets_s',
    'total_length_fwd_packets',
    'subflow_fwd_bytes',
    'flow_packets_s',
    'packet_length_std',
    'flow_iat_mean',
    'avg_fwd_segment_size',
    'flow_iat_max',
    'init_win_bytes_backward',
    'avg_bwd_segment_size',
    'bwd_packet_length_mean',
    'flow_duration',
    'bwd_packet_length_std',
    'bwd_packet_length_max',
    'subflow_bwd_bytes',
    'total_length_bwd_packets',
    'destination_port',
    'packet_length_variance'
]
# @app.route('/predict', methods=['GET', 'POST'])
# def packet_form():
#     result = None
#     if request.method == 'POST':
#         try:
#             # Collect form inputs in order
#             input_data = []
#             for feature in FEATURES:
#                 value = request.form.get(feature)
#                 if value is None or value.strip() == '':
#                     return render_template('form.html', result=f"Error: {feature} is required.")
#                 input_data.append(float(value))
            
#             # Convert to numpy array and reshape for prediction
#             input_array = np.array(input_data).reshape(1, -1)
            
#             # Predict using the stacking model
#             prediction = model.predict(input_array)[0]
            
#             # If it's classification, you can map numeric to labels
#             result = f"Predicted Value: {prediction}"
        
#         except ValueError:
#             result = "Invalid input! Please enter numeric values only."
#         except Exception as e:
#             result = f"Error: {str(e)}"

#     return render_template('dashboard.html', result=result)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))

    def __init__(self,email,password,name):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    def check_password(self,password):
        return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))

with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('home.html')

@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        # handle request
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        new_user = User(name=name,email=email,password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect('/login')




    return render_template('register.html')

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            session['email'] = user.email
            return redirect('/dashboard')
        else:
            return render_template('login.html',error='Invalid user')

    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if session['email']:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html',user=user)
    
    return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)