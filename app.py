from flask import Flask, request,render_template, redirect,session,Response,flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from model import db,User
import bcrypt
import joblib
import numpy as np
import sklearn
global filename

filename=""


app = Flask(__name__)

#load the model
# model = joblib.load('model/StackingEnsemble.joblib')
#configure your database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Bind the SQLAlchemy object to your Flask app
db.init_app(app)


app.secret_key = 'secret_key'

# from youtube tutorial

app.config['SESSION_TYPE'] = 'filesystem'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

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

# class User(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     name = db.Column(db.String(100), nullable=False)
#     email = db.Column(db.String(100), unique=True)
#     password = db.Column(db.String(100))

#     def __init__(self,email,password,name):
#         self.name = name
#         self.email = email
#         self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
#     def check_password(self,password):
#         return bcrypt.checkpw(password.encode('utf-8'),self.password.encode('utf-8'))


with app.app_context():
    db.create_all()


@app.route('/')
def home():
    return render_template('home.html')

# @app.route('/register',methods=['GET','POST'])
# def register():
#     if request.method == 'POST':
#         # handle request
#         name = request.form['name']
#         email = request.form['email']
#         password = request.form['password']
       

#         new_user = User(name=name,email=email,password=password)
#         db.session.add(new_user)
#         db.session.commit()
#         return redirect('/login')


@app.route('/register', methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form.get('confirm_password')

        # Validate
        if not name or not email or not password:
            flash("Please fill in all fields", "error")
            return redirect('/register')

        if password != confirm_password:
            flash("Passwords do not match", "error")
            return redirect('/register')

        # Check if user exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash("Email already registered. Please login.", "error")
            return redirect('/register')

        # Create new user with hashed password
        new_user = User(name=name, email=email)
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect('/login')

    return render_template('register.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):
            session['email'] = user.email
            flash("Login successful!", "success")
            return redirect('/dashboard')
        else:
            flash("Invalid email or password", "error")
            return redirect('/login')

    return render_template('login.html')

# @app.route('/dashboard')
# def dashboard():
#     if session['email']:
#         user = User.query.filter_by(email=session['email']).first()
#         return render_template('dashboard.html',user=user)
    
#     return redirect('/login')

@app.route('/dashboard')
def dashboard():
    if 'email' in session:
        user = User.query.filter_by(email=session['email']).first()
        return render_template('dashboard.html', user=user)
    else:
        flash("Please login first", "error")
        return redirect('/login')

@app.route('/logout')
def logout():
    session.pop('email',None)
    return redirect('/login')

# #{'Dos':0,'Probe':1,'R2L':2,'U2R':3,'Normal':4}
# def decode(output):
#     print(output)
#     if output==0:
#         return 'Dos Attack Found in Packet'
#     elif output==1:
#         return 'Probe Attack Found in Packet'
#     elif output==2:
#         return 'R2L Attack Found in Packet'
#     elif output==3:
#         return 'U2R Attack Found in Packet'
#     elif output==4:
#         return 'Normal Packet'


import os
import pandas as pd
model_filename='model/StackingEnsemble.joblib'
loaded_model = joblib.load(model_filename)

# print(loaded_model.feature_names_in_)
#Reverse mapping dictionary to decode predicted class
class_mapping_reverse={
    0:'BENIGN',
    1:'Bot',
    2:'DDoS',
    3:'DoS GoldenEye',
    4:'DoS Hulk',
    5:'DoS Slowhttptest',
    6:'DoS slowloris',
    7:'FTP-Patator',
    8:'Heartbleed',
    9:'Infiltration',
    10:'PortScan',
    11:'SSH-Patator',
    12:'Web Attack � Brute Force',
    13:'Web Attack � Sql Injection',
    14:'Web Attack � XSS'    
}


# List of features in the exact order
feature_order=[
   ['Fwd Packet Length Max',
 'Fwd Packet Length Mean',
 'Bwd Packets/s',
 'Total Length of Fwd Packets',
 'Subflow Fwd Bytes',
 'Flow Packets/s',
 'Packet Length Std',
 'Flow IAT Mean',
 'Avg Fwd Segment Size',
 'Flow IAT Max',
 'Init_Win_bytes_backward',
 'Avg Bwd Segment Size',
 'Bwd Packet Length Mean',
 'Flow Duration',
 'Bwd Packet Length Std',
 'Bwd Packet Length Max',
 'Subflow Bwd Bytes',
 'Total Length of Bwd Packets',
 'Destination Port',
 'Packet Length Variance']
]
# def preprocess_input(user_input):
#     #convert input to the appropriate data types
#     for column in feature_order:
#         user_input[column] = float(user_input[column])
#     return pd.DataFrame([user_input])
def preprocess_input(user_input):
    """
    Converts user input values to float and returns a DataFrame
    user_input: dict of form inputs
    """
    processed_input = {}
    for column in feature_order:
        value = user_input.get(column)
        if value is None or value == '':
            raise ValueError(f"Missing value for {column}")
        try:
            processed_input[column] = float(value)
        except ValueError:
            raise ValueError(f"Invalid numeric value for {column}: {value}")
    return pd.DataFrame([processed_input])


from flask import Flask,jsonify

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    result = None
    try:
        if request.method == 'POST':
            user_input = dict(request.form)
            # Preprocess
            user_data = preprocess_input(user_input)

            # Prediction
            prediction = loaded_model.predict(user_data)[0]
            decoded_class = class_mapping_reverse.get(prediction, 'Unknown')
            result = f"Prediction: {decoded_class}"

    except Exception as e:
        print(f"Error: {e}")
        result = f"Error: {str(e)}"

    return render_template('predict.html', result=result, feature_order=feature_order)



#store the prediction temporarily
last_prediction = []
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    global last_prediction
    #check if the post request has the file part
    if 'file' not in request.files:
        return render_template('upload.html',error='No file part')
    file = request.files['file']
    #if the user does not select a file, the browser also
    #submits an empty part without filename
    if file.filename == '':
        return render_template('upload.html',error='No selected file')
    try:
        #Read the csv file
        df=pd.read_csv(file)
       
        #Make predictions using the loaded model
        predictions = loaded_model.predict(df)
        #   Get the class names for prediction
        class_names=[class_mapping_reverse.get(prediction,'Unknown') for prediction in predictions]

        #convert the int64 types to native python integers
        predictions=predictions.astype(np.int64).tolist() 

        #prepare the response with both class index and class name
        response=[{'sr_no': i+1,'class_index':prediction,'class_name':class_name} 
                  for i, (prediction,class_name) in enumerate(zip(predictions,class_names))]

        #Store the last prediction
        last_prediction = response

        #Return the HTML page with predictions
        return render_template('upload.html',predictions=response)
    

    except Exception as e:
        return render_template('upload.html',error=f"Error processing file: {str(e)}")

@app.route('/download_report')
def download_report():
    global last_prediction
    if not last_prediction:
        return Response("No predictions available to download.", mimetype='text/plain')
    #Create CSV content
    report_lines=["Intrusion Detection Report\n"]
    report_lines = ["Sr No,Class Index,Class Name\n"]
    for item in last_prediction:
        line = f"{item['sr_no']},{item['class_index']},{item['class_name']}\n"
        report_lines.append(line)   
    report_content = ''.join(report_lines)
    return Response(
        report_content,
        mimetype='text/csv',
        headers={'Content-Disposition':'attachment;filename=network_intrusion_report.csv'}
    )



if __name__=='__main__':
    app.run(debug=True)